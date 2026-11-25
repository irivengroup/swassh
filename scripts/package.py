"""Create a complete source ZIP and SHA-256 manifest, excluding runtime caches."""

import hashlib
import json
import zipfile
from pathlib import Path

import tomllib

ROOT = Path(__file__).resolve().parents[1]
EXCLUDED = {
    ".git",
    ".venv",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "__pycache__",
    "htmlcov",
    ".swassh",
}


INCLUDED_ROOTS = {".github", "src", "tests", "scripts", "build_support", "benchmarks", "docs", "examples", "validation", "dist"}
INCLUDED_FILES = {".gitignore", "pyproject.toml", "README.md", "LICENSE", "VALIDATION.md", "SECURITY.md"}


def main() -> None:
    version = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    out = ROOT / "dist"
    out.mkdir(exist_ok=True)
    archive = out / f"swassh-{version}.zip"
    paths = []
    for path in sorted(ROOT.rglob("*")):
        relative = path.relative_to(ROOT)
        # Raw installation output contains workstation paths and subprocess
        # output. Only separately reviewed, sanitized evidence is deliverable.
        if relative.as_posix() in {'validation/installation.json','validation/runtime-diagnostics.jsonl'}:
            continue
        if relative.parts[0] == 'validation' and any(part.startswith('child-coverage-') for part in relative.parts[1:]):
            continue  # Transient measurement catalogs/journals are retained as local evidence.
        if relative.parts[0] not in INCLUDED_ROOTS and relative.as_posix() not in INCLUDED_FILES:
            continue
        if EXCLUDED.intersection(relative.parts):
            continue
        if path.name in {".coverage", "coverage.xml", "SHA256SUMS"} or relative.as_posix() == 'MANIFEST.json':
            continue
        if "dist" in relative.parts and path.name not in {
            f"swassh-{version}-py3-none-any.whl", f"swassh-{version}.tar.gz"
        }:
            continue
        if path.is_symlink():
            raise ValueError(f"symbolic link forbidden in deliverable: {relative}")
        if not path.is_file():
            continue
        if path.stat().st_size == 0:

            raise ValueError(f"empty deliverable: {relative}")
        paths.append(path)
    required = [
        'src/swassh/domain/endpoints.py',
        'src/swassh/domain/hosts.py',
        'src/swassh/domain/byte_credits.py',
        'src/swassh/domain/credit_state.py',
        'src/swassh/infrastructure/admission_deadline.py',
        'src/swassh/infrastructure/native_ready.py',
        'tests/test_native_readiness_contracts.py',
        'tests/test_pacing_clock_contracts.py',
        'src/swassh/application/task_ownership.py',
        'src/swassh/infrastructure/native_budget.py',
        'src/swassh/infrastructure/json_data.py',
        'src/swassh/infrastructure/socket_relay.py',
        'src/swassh/infrastructure/relay_connect.py',
        'src/swassh/infrastructure/database/migration/encrypted_bytes_v2.py',
        'scripts/coverage_child.py',
        'scripts/coverage_processes.py',
        'scripts/coverage_source.py',
        'tests/test_source_coverage.py',
        'tests/test_nop_coverage.py',
        'tests/test_control_coverage.py',
        'tests/control_cases/decisions.py',
        'tests/test_runtime_coverage.py',
        'tests/runtime_cases/decisions.py',
        'tests/test_trace_coverage.py',
        'tests/test_extended_coverage.py',
        'tests/extended_cases/decisions.py',
        'tests/statement_cases/decisions.py',
        'tests/source_cases/decisions.py',
        'tests/source_unsupported_cases/decisions.py',
        'scripts/import_policy.py',
        'tests/test_adapter_contracts.py',
        'tests/test_audit_storage_contracts.py',
        'tests/test_channel_input_contracts.py',
        'tests/test_cli_execution_ports.py',
        'tests/test_convergence_storage_failures.py',
        'tests/test_native_cleanup_contracts.py',
        'tests/test_native_staging_lifecycle.py',
        'tests/test_network_relay_integration.py',
        'tests/test_network_failure_contracts.py',
        'tests/test_channel_scope_ownership.py',
        'tests/test_transfer_cancellation_contracts.py',
        'tests/test_report_worker_parent_protocol.py',
        'tests/test_schema_refusal_contracts.py',
        'tests/test_windows_filesystem_boundary.py',
        'tests/test_input_snapshot_boundaries.py',
        'tests/test_fdpass_socket_contract.py',
        'tests/test_tcp_proxy_lifecycle.py',
        'tests/coverage_compiler_cases/dispatch.py',
        'tests/coverage_source_identity_cases/identity.py',
        'tests/test_cli_management_contracts.py',
        'tests/test_client_ownership_contracts.py',
        'tests/test_installation_boundary_contracts.py',
        'tests/test_live_output_failures.py',
        'tests/test_preflight_boundary_contracts.py',
        'tests/test_reporter_shutdown_contracts.py',
        'tests/test_spool_failure_contracts.py',
        'tests/test_transfer_publication_contracts.py',
        'tests/test_workflow_store_failures.py',
        'tests/test_application_resilience.py',
        'tests/test_byte_budget_failures.py',
        'tests/test_byte_credits.py',
        'tests/test_admission_deadline.py',
        'tests/test_admission_deadline_hint.py',
        'tests/test_credit_state_compatibility.py',
        'tests/test_ssh_failure_boundaries.py',
        'tests/test_composition_contracts.py',
        'tests/test_configuration_matrix.py',
        'tests/test_connector_contracts.py',
        'tests/test_coverage_metrics.py',
        'tests/test_coverage_diagnostics.py',
        'tests/test_domain_boundaries.py',
        'tests/test_filesystem_contracts.py',
        'tests/test_guardian_relay.py',
        'tests/test_import_policy.py',
        'tests/test_inventory_boundaries.py',
        'tests/test_native_control_contracts.py',
        'tests/test_process_guard_contracts.py',
        'tests/test_public_annotations.py',
        'tests/test_relay_failures.py',
        'tests/test_resource_boundaries.py',
        'tests/test_shared_budget_failures.py',
        'tests/test_task_ownership.py',
        'tests/test_terminal_contracts.py',
        'tests/test_timeout_boundaries.py',
        'tests/test_transfer_failure_contracts.py',
        'tests/test_windows_failure_contracts.py',
        'tests/test_workflow_boundaries.py',
        'benchmarks/core.py',
        'docs/index.md',
        'docs/wiki.d/usage/CONVERGENCE.md',
        'docs/wiki.d/usage/WORKFLOWS.md',
        'docs/wiki.d/usage/CHANNELS.md',
        'docs/wiki.d/operations/BANDWIDTH.md',
        'scripts/wiki.py',
        'scripts/coverage_metrics.py',
        'scripts/coverage_diagnostics.py',
        'examples/desired-state.json',
        'examples/workflow.json',
        'src/swassh/domain/convergence.py',
        'src/swassh/domain/workflows.py',
        'src/swassh/domain/channels.py',
        'src/swassh/domain/bandwidth.py',
        'src/swassh/application/convergence.py',
        'src/swassh/application/workflows.py',
        'src/swassh/application/workflow_contracts.py',
        'src/swassh/application/durable.py',
        'src/swassh/infrastructure/convergence.py',
        'src/swassh/infrastructure/workflow_store.py',
        'src/swassh/infrastructure/workflow_execution.py',
        'src/swassh/infrastructure/channels.py',
        'src/swassh/infrastructure/bandwidth.py',
        'src/swassh/infrastructure/tcp_proxy.py',
        'src/swassh/infrastructure/database/migration/convergence_v1.py',
        'src/swassh/infrastructure/database/migration/workflows_v1.py',
        'src/swassh/interfaces/convergence.py',
        'src/swassh/interfaces/workflows.py',
        'src/swassh/interfaces/channels.py',
        'tests/test_convergence.py',
        'tests/test_workflows.py',
        'tests/test_channels.py',
        'tests/test_bandwidth.py',
        'tests/test_wiki.py',
        'src/swassh/application/admission.py',
        'src/swassh/application/boundaries.py',
        'src/swassh/infrastructure/bastion.py',
        'src/swassh/infrastructure/process_guard.py',
        'src/swassh/infrastructure/windows.py',
        'src/swassh/infrastructure/preview.py',
        'src/swassh/infrastructure/integrity.py',
        'src/swassh/infrastructure/progress.py',
        'tests/test_improvements.py',
        'docs/wiki.d/history/hardening/HARDENING-1.4.0.md',
        "pyproject.toml",
        "README.md",
        "LICENSE",
        "src/swassh/interfaces/cli.py",
        "src/swassh/application/swarm.py",
        "src/swassh/application/ports.py",
        "src/swassh/domain/models.py",
        "src/swassh/bootstrap.py",
        "src/swassh/infrastructure/process_reporter.py",
        "tests/test_architecture.py",
        "tests/test_transport.py",
        "tests/test_transfers.py",
        "src/swassh/domain/transfers.py",
        "src/swassh/application/transfers.py",
        "src/swassh/application/transfer_settings.py",
        "src/swassh/infrastructure/transfers.py",
        "src/swassh/interfaces/transfers.py",
        "docs/wiki.d/usage/TRANSFERS.md",
        "docs/wiki.d/usage/SCHEDULING.md",
        "src/swassh/domain/scheduling.py",
        "src/swassh/application/scheduling.py",
        "src/swassh/application/schedule_contracts.py",
        "src/swassh/infrastructure/schedule_store.py",
        "src/swassh/infrastructure/scheduled_execution.py",
        "src/swassh/interfaces/scheduling.py",
        "scripts/scheduler_service.py",
        "tests/test_scheduling.py",
        "tests/test_scheduler_service.py",
        "tests/test_hardening_massive.py",
        "docs/wiki.d/history/hardening/HARDENING-1.3.1.md",
        "docs/wiki.d/history/IMPROVEMENTS.md",
        "docs/wiki.d/operations/PORTABILITY.md",
        "tests/test_portability.py",
        "scripts/platform_gate.py",
        "scripts/remote_portability.py",
        ".github/workflows/portability.yml",
        ".github/workflows/ci.yml",
        ".github/workflows/release.yml",
    ]
    for name in required:
        if ROOT / name not in paths:
            raise ValueError(f"missing deliverable: {name}")
    manifest = {
        path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in paths
    }
    # Keep the workspace receipt consistent with the manifest embedded in the
    # source ZIP; neither manifest includes itself in its hash inventory.
    (ROOT/'MANIFEST.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8',newline='\n')
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as stream:
        for path in paths:
            relative = path.relative_to(ROOT).as_posix()
            entry = zipfile.ZipInfo(f"swassh-{version}/{relative}", (1980, 1, 1, 0, 0, 0))
            entry.create_system = 3
            entry.external_attr = (0o100755 if relative == 'tests/fake_ssh.py' else 0o100644) << 16
            entry.compress_type = zipfile.ZIP_DEFLATED
            stream.writestr(entry, path.read_bytes())
        entry = zipfile.ZipInfo(f"swassh-{version}/MANIFEST.json", (1980, 1, 1, 0, 0, 0))
        entry.create_system = 3
        entry.external_attr = 0o100644 << 16
        entry.compress_type = zipfile.ZIP_DEFLATED
        stream.writestr(entry, json.dumps(manifest, indent=2) + "\n")
    with zipfile.ZipFile(archive) as stream:
        if stream.testzip() is not None:
            raise ValueError("ZIP integrity failure")
        for name, digest in manifest.items():
            if (
                hashlib.sha256(stream.read(f"swassh-{version}/{name}")).hexdigest()
                != digest
            ):
                raise ValueError(f"manifest mismatch: {name}")
    artifacts = [archive, out / f"swassh-{version}-py3-none-any.whl",
                 out / f"swassh-{version}.tar.gz"]
    (out / "SHA256SUMS").write_text(
        "".join(
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
            for path in artifacts
        )
    )
    print(f"Verified {len(paths)} populated files: {archive}")


if __name__ == "__main__":
    main()
