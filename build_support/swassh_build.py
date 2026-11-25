"""Minimal PEP 517 backend and wheel builder, using only the standard library."""

from __future__ import annotations

import base64
import csv
import hashlib
import gzip
import io
import tarfile
import zipfile
from pathlib import Path

import tomllib

ROOT = Path(__file__).resolve().parents[1]
EXCLUDED = {
    ".git",
    ".venv",
    "__pycache__",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
    "htmlcov",
    "dist",
    ".swassh",
}


INCLUDED_ROOTS = {".github", "src", "tests", "scripts", "build_support", "benchmarks", "docs", "examples", "validation", "dist"}
INCLUDED_FILES = {".gitignore", "pyproject.toml", "README.md", "LICENSE", "VALIDATION.md", "SECURITY.md"}


def _project():
    return tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]


def _metadata():
    project = _project()
    return (
        f"Metadata-Version: 2.1\nName: swassh\nVersion: {project['version']}\n"
        f"Summary: {project['description']}\nAuthor: Alfred TCHONDJO\nLicense: MIT\n"
        + ''.join(f"Classifier: {value}\n" for value in project.get('classifiers', []))
        + "Requires-Python: >=3.11\nDescription-Content-Type: text/markdown\n\n"
        + (ROOT / "README.md").read_text(encoding="utf-8")
    ).encode()


def _dist_info():
    return f"swassh-{_project()['version']}.dist-info"


def prepare_metadata_for_build_wheel(metadata_directory, config_settings=None):
    path = Path(metadata_directory) / _dist_info()
    path.mkdir(parents=True, exist_ok=True)
    (path / "METADATA").write_bytes(_metadata())
    (path / "WHEEL").write_text(
        "Wheel-Version: 1.0\nGenerator: swassh-stdlib\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
    )
    return path.name


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    name = f"swassh-{_project()['version']}-py3-none-any.whl"
    output = Path(wheel_directory) / name
    output.parent.mkdir(parents=True, exist_ok=True)
    for path in (ROOT / "src", ROOT / "src/swassh", ROOT / "README.md", ROOT / "LICENSE", ROOT / "pyproject.toml"):
        if path.is_symlink():
            raise ValueError("source distribution must not include symbolic links")
    for path in (ROOT / "src/swassh").rglob("*"):
        if "__pycache__" not in path.parts and path.is_symlink():
            raise ValueError("source distribution must not include symbolic links")
    files = {
        str(path.relative_to(ROOT / "src")).replace("\\", "/"): path.read_bytes()
        for path in (ROOT / "src/swassh").rglob("*")
        if path.is_file() and "__pycache__" not in path.parts
    }
    info = _dist_info()
    files[f"{info}/METADATA"] = _metadata()
    files[f"{info}/WHEEL"] = (
        b"Wheel-Version: 1.0\nGenerator: swassh-stdlib\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
    )
    files[f"{info}/entry_points.txt"] = (
        "[console_scripts]\n"
        + "".join(f"{name} = {target}\n" for name, target in _project()["scripts"].items())
    ).encode()
    files[f"{info}/licenses/LICENSE"] = (ROOT / "LICENSE").read_bytes()
    record = io.StringIO(newline="")
    writer = csv.writer(record)
    for path, data in sorted(files.items()):
        digest = (
            base64.urlsafe_b64encode(hashlib.sha256(data).digest())
            .rstrip(b"=")
            .decode()
        )
        writer.writerow((path, "sha256=" + digest, len(data)))
    writer.writerow((f"{info}/RECORD", "", ""))
    files[f"{info}/RECORD"] = record.getvalue().encode()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for path, data in sorted(files.items()):
            entry = zipfile.ZipInfo(path, (1980, 1, 1, 0, 0, 0))
            entry.create_system = 3
            entry.external_attr = 0o100644 << 16
            entry.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(entry, data)
    return name


def build_sdist(sdist_directory, config_settings=None):
    version = _project()["version"]
    name = f"swassh-{version}.tar.gz"
    output = Path(sdist_directory) / name
    output.parent.mkdir(parents=True, exist_ok=True)
    # No wall-clock timestamps, host uid/gid, or temporary filename in artifacts.
    with output.open('wb') as raw, gzip.GzipFile(fileobj=raw, filename='', mode='wb', mtime=0) as zipped, \
            tarfile.open(fileobj=zipped, mode='w', format=tarfile.PAX_FORMAT) as archive:
        for path in sorted(ROOT.rglob("*")):
            relative = path.relative_to(ROOT)
            # Keep raw local qualification transcripts out of source releases.
            if relative.as_posix() in {'validation/installation.json','validation/runtime-diagnostics.jsonl'}:
                continue
            if relative.parts[0] == 'validation' and any(part.startswith('child-coverage-') for part in relative.parts[1:]):
                continue
            if relative.parts[0] not in INCLUDED_ROOTS and relative.as_posix() not in INCLUDED_FILES:
                continue
            if (
                EXCLUDED.intersection(relative.parts)
                or path.name == ".coverage"
            ):
                continue
            if path.is_symlink():
                raise ValueError("source distribution must not include symbolic links")
            if not path.is_file():
                continue
            data = path.read_bytes()
            info = tarfile.TarInfo(f"swassh-{version}/{relative.as_posix()}")
            info.size = len(data)
            info.mode = 0o755 if relative.as_posix() == 'tests/fake_ssh.py' else 0o644
            archive.addfile(info, io.BytesIO(data))
    return name


def get_requires_for_build_wheel(config_settings=None):
    return []


def get_requires_for_build_sdist(config_settings=None):
    return []
