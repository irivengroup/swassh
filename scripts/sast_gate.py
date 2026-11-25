"""SAST-v2 qualification: full raw scan, externally anchored individual review.

Run only through the operator's trusted bootstrap, which verifies this file's
expected SHA-256 before loading it. A candidate cannot supply that expectation
or its own review authority. This gate grants security qualification only;
quality, installation, reproducibility and publication remain separate gates.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import zipfile


SCOPE = ('src', 'tests', 'scripts', 'build_support', 'benchmarks')
SOURCE_ROOTS = SCOPE + ('.github', 'docs', 'examples')
SOURCE_FILES = ('.gitignore', 'pyproject.toml', 'README.md', 'LICENSE', 'VALIDATION.md', 'SECURITY.md')
VERSIONS = {'bandit': '1.9.4', 'colorama': '0.4.6', 'markdown-it-py': '4.2.0',
            'mdurl': '0.1.2', 'pygments': '2.21.0', 'pyyaml': '6.0.3',
            'rich': '15.0.0', 'stevedore': '5.9.1'}


class Refusal(ValueError):
    """A failed, missing or inconsistent mandatory SAST-v2 precondition."""


def sha(raw: bytes) -> str:
    """Hash original bytes, never a decoded or normalized source copy."""
    return hashlib.sha256(raw).hexdigest()


def canonical(value) -> bytes:
    """Deterministic signal encoding; raw scanner bytes are retained separately."""
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def load_json(raw: bytes):
    """Reject duplicate fields and non-JSON numeric constants, not just bad syntax."""
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise Refusal('duplicate JSON field: '+key)
            result[key] = value
        return result

    def constant(value):
        raise Refusal('non-JSON numeric constant: '+value)

    return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)


def digest(value):
    """Validate a strict SHA-256 identity supplied by the trusted operator."""
    if not isinstance(value, str) or re.fullmatch('[0-9a-f]{64}', value) is None:
        raise Refusal('missing or malformed trusted SHA-256')
    return value


def relative(value):
    """Accept only canonical relative POSIX identities, with no aliasing."""
    if not isinstance(value, str) or not value or '\\' in value or ':' in value:
        raise Refusal('invalid source path')
    path = PurePosixPath(value)
    if path.is_absolute() or path.as_posix() != value or '..' in path.parts:
        raise Refusal('noncanonical source path')
    return value


def linked_within(path: Path, boundary: Path) -> bool:
    """Inspect real link/reparse attributes through the owned input boundary.

    Windows short/long names can resolve differently without being links.
    Comparing normalized spellings would reject ordinary files while failing
    to explain their actual trust properties. Never follow a reparse component.
    """
    parts = path.relative_to(boundary).parts
    current = boundary
    for part in (None, *parts):
        if part is not None:
            current = current/part
        info = current.lstat()
        if (stat.S_ISLNK(info.st_mode)
                or getattr(info, 'st_file_attributes', 0) & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400)):
            return True
    return False


class SourceSnapshot:
    """Bind reviews to clean maintained inputs before any quality/build command.

    Only operator metadata/private QA directories are outside the source set.
    Reject other root members and compiled application caches instead of
    silently omitting a possible caller or a prebuilt release artifact.
    """

    @staticmethod
    def capture(root: Path) -> dict[str, str]:
        result = {}
        allowed = set(SOURCE_FILES + SOURCE_ROOTS) | {'.git', '.qa-bandit', '.qa-approved-review'}
        for entry in root.iterdir():
            if linked_within(entry, root):
                raise Refusal('linked source root member: '+entry.name)
            if entry.name not in allowed:
                raise Refusal('unreviewed source root member: '+entry.name)
        for name in SOURCE_FILES + SOURCE_ROOTS:
            base = root/name
            if not base.exists() or linked_within(base, root):
                raise Refusal('missing or linked source: '+name)
            paths = base.rglob('*') if base.is_dir() else (base,)
            for path in paths:
                name = path.relative_to(root).as_posix()
                # -B does not prevent existing caches from being loaded by
                # later quality commands. The scan input must be a clean tree.
                if ('__pycache__' in {part.casefold() for part in path.relative_to(root).parts}
                        or path.suffix.casefold() == '.pyc'):
                    raise Refusal('compiled source cache is not a reviewed input: '+name)
                if linked_within(path, root):
                    raise Refusal('linked source: '+name)
                if not path.is_file() and not path.is_dir():
                    raise Refusal('non-regular source entry: '+name)
                if path.is_file():
                    result[relative(name)] = sha(path.read_bytes())
        if not result:
            raise Refusal('empty source snapshot')
        return dict(sorted(result.items()))


class ReviewPolicy:
    """Check an exact scan/review pair against a detached operator authority.

    This class does not infer that a warning is benign from its severity, rule
    or frequency. The external reviewer is responsible for the correctness of
    its contextual assessment and evidence, including relevant callers.
    """

    def __init__(self, review_bytes: bytes, expected_review_sha256: str, now: datetime):
        if sha(review_bytes) != digest(expected_review_sha256):
            raise Refusal('review is not the externally approved document')
        self.review = load_json(review_bytes)
        self.now = now

    def verify_sources(self, sources):
        """Verify detached input authority before installing candidate QA locks.

        This pure preflight does not approve scanner results or publication.
        The complete scan and individual evaluation are still mandatory.
        """
        review = self.review
        fields = {'schema', 'contract', 'source_files', 'toolchain', 'reviewer',
                  'issued_at', 'expires_at', 'records', 'evidence'}
        if not isinstance(review, dict) or set(review) != fields:
            raise Refusal('review schema differs')
        if review['schema'] != 'swassh-sast-review/2' or review['contract'] != 'SAST-v2':
            raise Refusal('review contract differs')
        if not isinstance(sources, dict) or not sources:
            raise Refusal('missing verified source inventory')
        for name, value in sources.items():
            relative(name)
            digest(value)
        if review['source_files'] != sources:
            raise Refusal('source, caller or control changed since review')
        if not isinstance(review['toolchain'], dict) or not review['toolchain']:
            raise Refusal('reviewed toolchain is missing')
        if not isinstance(review['reviewer'], str) or not review['reviewer'].strip():
            raise Refusal('review authority identity is missing')
        try:
            issued = datetime.fromisoformat(review['issued_at'])
            expires = datetime.fromisoformat(review['expires_at'])
            if issued.utcoffset() is None or expires.utcoffset() is None:
                raise ValueError('timezone missing')
            current = issued <= self.now < expires
        except (TypeError, ValueError):
            raise Refusal('invalid review validity interval') from None
        if not current:
            raise Refusal('review is premature or expired')
        evidence = review['evidence']
        if not isinstance(evidence, dict):
            raise Refusal('review evidence inventory is missing')
        for name, value in evidence.items():
            relative(name)
            digest(value)
        return review['toolchain']

    def evaluate(self, sources, report, raw_exit, toolchain):
        """Return only a security result; reject all incomplete attestations."""
        review = self.review
        if self.verify_sources(sources) != toolchain or not isinstance(toolchain, dict) or not toolchain:
            raise Refusal('reviewed toolchain differs')
        evidence = review['evidence']
        if not isinstance(report, dict) or set(report) != {'errors', 'generated_at', 'metrics', 'results'}:
            raise Refusal('incomplete or unexpected raw Bandit report')
        if type(raw_exit) is not int or raw_exit not in (0, 1) or report['errors'] != []:
            raise Refusal('scanner failed or reported analysis errors')
        findings, metrics = report['results'], report['metrics']
        if not isinstance(findings, list) or not isinstance(metrics, dict) or '_totals' not in metrics:
            raise Refusal('raw scan inventory is missing')
        expected_files = {name for name in sources if name.endswith('.py') and name.split('/')[0] in SCOPE}
        if set(metrics) - {'_totals'} != expected_files:
            raise Refusal('scanner omitted or substituted Python sources')
        metric_fields = {'loc', 'nosec', 'skipped_tests'} | {
            kind+'.'+level for kind in ('CONFIDENCE', 'SEVERITY')
            for level in ('HIGH', 'MEDIUM', 'LOW', 'UNDEFINED')}
        for counts in metrics.values():
            if (not isinstance(counts, dict) or set(counts) != metric_fields
                    or any(type(value) is not int or value < 0 for value in counts.values())
                    or counts['nosec'] != 0 or counts['skipped_tests'] != 0):
                raise Refusal('incomplete, filtered or inconsistent scan metrics')
        for field in metric_fields:
            if metrics['_totals'][field] != sum(metrics[name][field] for name in expected_files):
                raise Refusal('scan metric totals contradict file inventory')
        for kind in ('SEVERITY', 'CONFIDENCE'):
            if sum(metrics['_totals'][kind+'.'+level] for level in ('HIGH', 'MEDIUM', 'LOW', 'UNDEFINED')) != len(findings):
                raise Refusal('scan metric totals contradict raw findings')
        if raw_exit != (1 if findings else 0):
            raise Refusal('raw exit contradicts raw findings')
        records = review['records']
        if not isinstance(records, list) or len(records) != len(findings):
            raise Refusal('individual review does not cover the exact raw set')
        approved = {}
        for record in records:
            required = {'signal', 'signal_sha256', 'source_sha256', 'assessment', 'approved',
                        'confirmed_defect', 'open_risk', 'trust_boundary', 'data_flow',
                        'rationale', 'positive_evidence', 'negative_evidence', 'limits'}
            if not isinstance(record, dict) or set(record) != required:
                raise Refusal('individual review schema differs')
            signal = record['signal']
            key = sha(canonical(signal))
            if record['signal_sha256'] != key or key in approved:
                raise Refusal('duplicate or altered individual signal')
            if (record['assessment'] != 'warning-without-confirmed-defect'
                    or record['approved'] is not True or record['confirmed_defect'] is not False
                    or record['open_risk'] is not False):
                raise Refusal('pending review, confirmed defect or unresolved risk')
            for field in ('trust_boundary', 'data_flow', 'rationale', 'limits'):
                if not isinstance(record[field], str) or not record[field].strip():
                    raise Refusal('contextual review is incomplete: '+field)
            for field in ('positive_evidence', 'negative_evidence'):
                references = record[field]
                if (not isinstance(references, list) or not references
                        or any(not isinstance(ref, str) or ref not in evidence for ref in references)):
                    raise Refusal('individual review lacks verified evidence: '+field)
            approved[key] = record
        seen = set()
        for signal in findings:
            if not isinstance(signal, dict):
                raise Refusal('invalid raw signal')
            name = relative(signal.get('filename'))
            key = sha(canonical(signal))
            if key in seen or key not in approved or name not in expected_files:
                raise Refusal('unknown, duplicate or displaced raw signal')
            record = approved[key]
            if record['source_sha256'] != sources[name]:
                raise Refusal('signal source differs from reviewed bytes')
            seen.add(key)
        return {'contract': 'SAST-v2', 'security_qualified': True,
                'raw_exit': raw_exit, 'raw_findings': len(findings),
                'individually_approved': len(seen), 'publication_authorized': False}


class Scanner:
    """Execute only the fixed, complete scan in a private output directory."""

    def __init__(self, root: Path, python: Path, wheels: Path, output: Path):
        self.root, self.python, self.wheels, self.output = root, python, wheels, output

    def attest_toolchain(self):
        """Compare installed scanner bytes to the locked original wheel bytes.

        The Python executable and the bootstrap are operator trust boundaries.
        Hash-locked installation must already have succeeded in a private venv.
        """
        # Inspect import hooks and bytecode before starting the interpreter.
        # -B prevents new caches but does not prevent loading an existing .pyc.
        # The private venv must therefore be installed with --no-compile.
        prefix = self.python.absolute().parent.parent
        site = prefix/('Lib/site-packages' if os.name == 'nt' else 'lib/python3.12/site-packages')
        if not (prefix/'pyvenv.cfg').is_file() or not site.is_dir():
            raise Refusal('scanner must use a private Python 3.12 virtual environment')
        for path in site.rglob('*'):
            name = path.relative_to(site)
            if linked_within(path, prefix):
                raise Refusal('linked scanner installation')
            if not path.is_file() and not path.is_dir():
                raise Refusal('non-regular scanner entry')
            if path.suffix.casefold() == '.pth' or path.name.casefold().startswith(('sitecustomize.', 'usercustomize.')):
                raise Refusal('scanner has an uncontrolled site import hook')
            if path.suffix.casefold() == '.pyc' and name.parts[0] not in {'pip', 'setuptools', '_distutils_hack', 'pkg_resources'}:
                raise Refusal('scanner bytecode is not an original locked wheel member')
        lock_bytes = (self.root/'.github/bandit-requirements.txt').read_bytes()
        lock = lock_bytes.decode('utf-8')
        packages = {}
        for line in lock.splitlines():
            if not line or line.startswith('#'):
                continue
            match = re.fullmatch(r'([a-z-]+)==([0-9.]+)((?: --hash=sha256:[0-9a-f]{64})+)', line)
            if match is None or match[1] in packages:
                raise Refusal('invalid QA lock')
            packages[match[1]] = (match[2], set(re.findall(r'sha256:([0-9a-f]{64})', match[3])))
        if {name: value[0] for name, value in packages.items()} != VERSIONS:
            raise Refusal('unreviewed scanner versions')
        # The helper imports no candidate module and emits only stdlib metadata.
        helper = ('import sys,sysconfig,json,importlib.metadata as m; '
                  'print(json.dumps({"python":list(sys.version_info[:3]),'
                  '"site":sysconfig.get_path("purelib"),'
                  '"runtime":sys._base_executable,"platform":sys.platform,'
                  '"versions":{d.metadata["Name"].lower().replace("_","-"):d.version '
                  'for d in m.distributions()}}))')
        completed = subprocess.run([str(self.python), '-I', '-B', '-c', helper], check=True,
                                   capture_output=True, timeout=30, cwd=self.output)
        installed = load_json(completed.stdout)
        if installed['python'][:2] != [3, 12]:
            raise Refusal('security scanner requires Python 3.12')
        if any(installed['versions'].get(name) != value for name, value in VERSIONS.items()):
            raise Refusal('installed scanner version differs')
        if Path(installed['site']).resolve() != site.resolve():
            raise Refusal('scanner uses a different site-packages directory')
        attested = {}
        installed_paths = set()
        expected_files, installer_metadata = set(), set()
        wheels = list(self.wheels.glob('*.whl'))
        if len(wheels) != len(VERSIONS):
            raise Refusal('expected exactly eight locked scanner wheels')
        for wheel in wheels:
            bits = wheel.name.split('-')
            name = bits[0].lower().replace('_', '-')
            value = sha(wheel.read_bytes())
            if name not in packages or bits[1] != packages[name][0] or value not in packages[name][1] or name in attested:
                raise Refusal('scanner wheel differs from lock')
            attested[name] = {'version': bits[1], 'wheel_sha256': value}
            with zipfile.ZipFile(wheel) as archive:
                for member in archive.namelist():
                    if member.endswith('/') or '.data/' in member:
                        continue
                    expected_files.add(relative(member))
                    if member.endswith('.dist-info/RECORD'):
                        # pip rewrites RECORD and adds inert installation
                        # markers. Plugin metadata is never such an exception.
                        metadata = PurePosixPath(member).parent.as_posix()
                        installer_metadata.update((metadata+'/INSTALLER', metadata+'/REQUESTED'))
                        continue
                    target = site/relative(member)
                    if target.is_symlink() or target.read_bytes() != archive.read(member):
                        raise Refusal('installed scanner bytes differ: '+member)
                    if member.endswith(('.py', '.so', '.pyd')):
                        installed_paths.add(member)
        actual_code = {p.relative_to(site).as_posix() for p in site.rglob('*')
                       if p.is_file() and '__pycache__' not in {part.casefold() for part in p.parts}
                       and p.suffix.casefold() in ('.py', '.so', '.pyd')
                       and p.relative_to(site).parts[0] not in {'pip', 'setuptools', '_distutils_hack', 'pkg_resources'}}
        if actual_code != installed_paths:
            raise Refusal('scanner site contains unexpected executable code')
        # Extra dist-info files can register executable plugins without adding
        # a .py file or changing any original wheel member. Inventory all files
        # of the locked tools, retaining only the operator's bootstrap boundary.
        bootstrap = {'pip', 'setuptools', '_distutils_hack', 'pkg_resources'}
        bootstrap.update(name+'-'+version+'.dist-info' for name, version in installed['versions'].items()
                         if name in {'pip', 'setuptools'})
        actual_files = {p.relative_to(site).as_posix() for p in site.rglob('*')
                        if p.is_file() and p.relative_to(site).parts[0] not in bootstrap}
        if not expected_files <= actual_files or actual_files - (expected_files | installer_metadata):
            raise Refusal('scanner site contains missing or unreviewed installed file')
        for member in installer_metadata & actual_files:
            content = (site/member).read_bytes()
            if (member.endswith('/INSTALLER') and content not in (b'pip\n', b'pip\r\n')
                    or member.endswith('/REQUESTED') and content != b''):
                raise Refusal('scanner has unexpected installer metadata')
        return {'python': installed['python'], 'platform': installed['platform'],
                'runtime_sha256': sha(Path(installed['runtime']).read_bytes()),
                'lock_sha256': sha(lock_bytes), 'wheels': attested}

    def run(self):
        """Keep the actual exit and original JSON, including on refusal."""
        raw = self.output/'bandit-full.json'
        if raw.exists():
            raise Refusal('scanner output already exists')
        command = [str(self.python), '-I', '-B', '-m', 'bandit', '--recursive', *SCOPE,
                   '--ignore-nosec', '--format', 'json', '--output', str(raw)]
        with (self.output/'bandit.stdout.log').open('xb') as stdout, (self.output/'bandit.stderr.log').open('xb') as stderr:
            try:
                process = subprocess.run(command, cwd=self.root, stdout=stdout, stderr=stderr, timeout=300)
            except subprocess.TimeoutExpired:
                (self.output/'raw-exit.json').write_bytes(canonical({
                    'command': command, 'raw_exit': None, 'timed_out': True})+b'\n')
                raise
        receipt = {'command': command, 'raw_exit': process.returncode}
        (self.output/'raw-exit.json').write_bytes(canonical(receipt)+b'\n')
        # The digest and parsed view must describe the very same original
        # bytes, even if a later read would observe a replacement report.
        raw_bytes = raw.read_bytes()
        report = load_json(raw_bytes)
        # Bandit emits ./ paths; normalize only identities in the parsed view.
        # The file above remains the original scanner output, byte for byte.
        def name(value):
            if not isinstance(value, str):
                raise Refusal('invalid scanner filename')
            if os.name == 'nt':
                value = value.replace('\\', '/')
            return relative(value.removeprefix('./'))
        normalized = {}
        for key, value in report['metrics'].items():
            key = key if key == '_totals' else name(key)
            if key in normalized:
                raise Refusal('scanner path alias collision')
            normalized[key] = value
        report['metrics'] = normalized
        for signal in report['results']:
            signal['filename'] = name(signal['filename'])
        return report, process.returncode, sha(raw_bytes)


def main():
    """Consume detached review authority; emit a refusal receipt on any failure."""
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('root', 'scanner-python', 'wheels', 'review', 'evidence', 'output'):
        parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args()
    root, output = args.root.resolve(), args.output.resolve()
    # No self-review file or scanner output is allowed inside maintained inputs.
    for path in (args.review.resolve(), args.evidence.resolve(), output):
        if path == root or root in path.parents:
            raise Refusal('review/evidence/output must be outside candidate sources')
    output.mkdir(parents=True, exist_ok=False)
    result = {'contract': 'SAST-v2', 'security_qualified': False, 'publication_authorized': False}
    try:
        expected_gate = digest(os.environ.get('SWASSH_SAST_GATE_SHA256'))
        if sha(Path(__file__).read_bytes()) != expected_gate:
            raise Refusal('gate is not the operator-approved verifier')
        sources = SourceSnapshot.capture(root)
        # Resolving a POSIX venv's python symlink would discard its venv prefix.
        scanner = Scanner(root, args.scanner_python.absolute(), args.wheels.resolve(), output)
        tools = scanner.attest_toolchain()
        report, raw_exit, raw_sha = scanner.run()
        result.update(raw_exit=raw_exit, raw_report_sha256=raw_sha, raw_findings=len(report['results']))
        if SourceSnapshot.capture(root) != sources or scanner.attest_toolchain() != tools:
            raise Refusal('source or scanner changed during analysis')
        policy = ReviewPolicy(args.review.read_bytes(), os.environ.get('SWASSH_SAST_REVIEW_SHA256'),
                              datetime.now(timezone.utc))
        evidence = policy.review.get('evidence', {})
        if not isinstance(evidence, dict):
            raise Refusal('missing review evidence')
        for name, value in evidence.items():
            path = args.evidence/relative(name)
            if path.is_symlink() or args.evidence.resolve() not in path.resolve().parents or sha(path.read_bytes()) != digest(value):
                raise Refusal('review evidence bytes differ')
        result.update(policy.evaluate(sources, report, raw_exit, tools))
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, zipfile.BadZipFile) as error:
        result['refusal'] = type(error).__name__+': '+str(error)
    (output/'security.json').write_bytes(canonical(result)+b'\n')
    print(json.dumps(result, ensure_ascii=True))
    return 0 if result['security_qualified'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
