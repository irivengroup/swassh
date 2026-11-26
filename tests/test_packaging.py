"""Ensure nested DDD packages are complete in the installable distributions."""

import hashlib
import os
import json
import runpy
import tempfile
import tarfile
import unittest
import zipfile
from pathlib import Path

import tomllib

ROOT = Path(__file__).resolve().parents[1]


class PackagingTests(unittest.TestCase):
    def test_distributions_are_identical_after_source_timestamp_changes(self):
        backend = runpy.run_path(str(ROOT / 'build_support/swassh_build.py'))
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            before = {}
            for kind in ('wheel', 'sdist'):
                name = backend['build_' + kind](str(output / 'first'))
                before[kind] = (output / 'first' / name).read_bytes()
            source = ROOT / 'src/swassh/__init__.py'
            original = source.stat()
            try:
                os.utime(source, ns=(original.st_atime_ns, 1000000000000000000))
                for kind in ('wheel', 'sdist'):
                    name = backend['build_' + kind](str(output / 'second'))
                    self.assertEqual((output / 'second' / name).read_bytes(), before[kind])
            finally:
                os.utime(source, ns=(original.st_atime_ns, original.st_mtime_ns))

    def test_wheel_contains_every_source_and_canonical_entrypoint(self):
        backend = runpy.run_path(str(ROOT / "build_support/swassh_build.py"))
        project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
        with tempfile.TemporaryDirectory() as directory:
            name = backend["build_wheel"](directory)
            with zipfile.ZipFile(Path(directory) / name) as wheel:
                for path in (ROOT / "src/swassh").rglob("*"):
                    if path.is_file() and "__pycache__" not in path.parts:
                        relative = path.relative_to(ROOT / "src").as_posix()
                        self.assertEqual(wheel.read(relative), path.read_bytes())
                info = f"swassh-{project['version']}.dist-info"
                entrypoint = wheel.read(info + "/entry_points.txt").decode()
                self.assertIn("swassh = " + project["scripts"]["swassh"], entrypoint)
                self.assertEqual(project["scripts"]["swassh"], "swassh.interfaces.cli:main")
                self.assertIn("swassh-clean-restore = swassh.interfaces.restore_cleanup:main", entrypoint)
                self.assertIn("swassh-restore-workflows = swassh.interfaces.restore_workflows:main", entrypoint)
                self.assertNotIn("Requires-Dist:", wheel.read(info + "/METADATA").decode())
                self.assertIsNone(wheel.testzip())

    def test_package_requires_layered_modules_and_current_distributions(self):
        script = runpy.run_path(str(ROOT / "scripts/package.py"))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            names = [
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
                'docs/index.md', 'docs/wiki.d/usage/CONVERGENCE.md',
                'docs/wiki.d/usage/WORKFLOWS.md', 'docs/wiki.d/usage/CHANNELS.md',
                'docs/wiki.d/operations/BANDWIDTH.md', 'scripts/wiki.py',
                'scripts/coverage_metrics.py', 'scripts/coverage_diagnostics.py',
                'examples/desired-state.json', 'examples/workflow.json',
                'src/swassh/domain/convergence.py', 'src/swassh/domain/workflows.py',
                'src/swassh/domain/channels.py', 'src/swassh/domain/bandwidth.py',
                'src/swassh/application/convergence.py', 'src/swassh/application/workflows.py',
                'src/swassh/application/workflow_contracts.py', 'src/swassh/application/durable.py',
                'src/swassh/infrastructure/convergence.py', 'src/swassh/infrastructure/workflow_store.py',
                'src/swassh/infrastructure/workflow_execution.py', 'src/swassh/infrastructure/channels.py',
                'src/swassh/infrastructure/bandwidth.py', 'src/swassh/infrastructure/tcp_proxy.py',
                'src/swassh/infrastructure/database/migration/convergence_v1.py',
                'src/swassh/infrastructure/database/migration/workflows_v1.py',
                'src/swassh/interfaces/convergence.py', 'src/swassh/interfaces/workflows.py',
                'src/swassh/interfaces/channels.py', 'tests/test_convergence.py',
                'tests/test_workflows.py', 'tests/test_channels.py', 'tests/test_bandwidth.py', 'tests/test_wiki.py',
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
                "pyproject.toml", "README.md", "LICENSE", "src/swassh/interfaces/cli.py",
                "src/swassh/application/swarm.py", "src/swassh/application/ports.py",
                "src/swassh/domain/models.py", "src/swassh/bootstrap.py",
                "src/swassh/infrastructure/process_reporter.py", "tests/test_architecture.py",
                "tests/test_transfers.py", "src/swassh/domain/transfers.py",
                "src/swassh/application/transfers.py", "src/swassh/application/transfer_settings.py",
                "src/swassh/infrastructure/transfers.py", "src/swassh/interfaces/transfers.py", "docs/wiki.d/usage/TRANSFERS.md",
                "docs/wiki.d/usage/SCHEDULING.md", "src/swassh/domain/scheduling.py",
                "src/swassh/application/scheduling.py", "src/swassh/application/schedule_contracts.py",
                "src/swassh/infrastructure/schedule_store.py", "src/swassh/infrastructure/scheduled_execution.py",
                "src/swassh/interfaces/scheduling.py", "scripts/scheduler_service.py",
                "tests/test_scheduling.py", "tests/test_scheduler_service.py",
                "tests/test_hardening_massive.py", "docs/wiki.d/history/hardening/HARDENING-1.3.1.md", "docs/wiki.d/history/IMPROVEMENTS.md",
                "docs/wiki.d/operations/PORTABILITY.md", "tests/test_portability.py", "scripts/platform_gate.py",
                "scripts/remote_portability.py", ".github/workflows/portability.yml",
                "tests/test_transport.py", ".github/workflows/ci.yml",
                ".github/workflows/release.yml", "dist/swassh-0.0.0-py3-none-any.whl",
                "dist/swassh-1.0.1-py3-none-any.whl", "dist/swassh-1.0.1.tar.gz",
            ]
            for name in names:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("fixture content\n")
            (root / "pyproject.toml").write_text('[project]\nversion = "1.0.1"\n')
            (root / "credentials.env").write_text("not a deliverable")
            (root / 'validation').mkdir()
            (root / 'validation/installation.json').write_text('{"raw_transcript": "private workstation path"}')
            (root / 'validation/runtime-diagnostics.jsonl').write_text('{"message": "private runtime context"}\n')
            transient = root / 'validation/child-coverage-fixture'
            transient.mkdir()
            (transient / 'process.events').write_bytes(b'')
            (transient / 'campaign.json').write_text('{"temporary_measurement_catalog":true}\n')
            historical = root / 'validation/history-fixture/MANIFEST.json'
            historical.parent.mkdir()
            historical.write_text('{"historical_receipt": "preserved bytes"}\n')
            backend = runpy.run_path(str(ROOT / 'build_support/swassh_build.py'))
            backend['build_sdist'].__globals__['ROOT'] = root
            name = backend['build_sdist'](str(root / 'dist'))
            with tarfile.open(root / 'dist' / name) as source_archive:
                self.assertNotIn('swassh-1.0.1/validation/installation.json', source_archive.getnames())
                self.assertNotIn('swassh-1.0.1/validation/runtime-diagnostics.jsonl', source_archive.getnames())
                self.assertFalse(any('/validation/child-coverage-fixture/' in name for name in source_archive.getnames()))
            script["main"].__globals__["ROOT"] = root
            script["main"]()
            with zipfile.ZipFile(root / "dist/swassh-1.0.1.zip") as archive:
                self.assertNotIn(
                    "swassh-1.0.1/dist/swassh-0.0.0-py3-none-any.whl", archive.namelist()
                )
                self.assertNotIn("swassh-1.0.1/credentials.env", archive.namelist())
                self.assertNotIn('swassh-1.0.1/validation/installation.json', archive.namelist())
                self.assertNotIn('swassh-1.0.1/validation/runtime-diagnostics.jsonl', archive.namelist())
                self.assertFalse(any('/validation/child-coverage-fixture/' in name for name in archive.namelist()))
                self.assertEqual(archive.read('swassh-1.0.1/validation/history-fixture/MANIFEST.json'),
                                 historical.read_bytes())
                manifest = json.loads(archive.read("swassh-1.0.1/MANIFEST.json"))
                for name, digest in manifest.items():
                    self.assertEqual(
                        hashlib.sha256(archive.read("swassh-1.0.1/" + name)).hexdigest(), digest
                    )
            # Removing a newly required runtime or observer dependency cannot
            # yield an apparently complete deliverable. Old refusal cases below
            # remain unchanged.
            for missing in ('src/swassh/domain/endpoints.py', 'src/swassh/domain/hosts.py', 'src/swassh/domain/byte_credits.py', 'src/swassh/domain/credit_state.py', 'src/swassh/infrastructure/admission_deadline.py', 'src/swassh/infrastructure/native_ready.py', 'tests/test_native_readiness_contracts.py', 'tests/test_pacing_clock_contracts.py', 'src/swassh/application/task_ownership.py', 'src/swassh/infrastructure/native_budget.py', 'src/swassh/infrastructure/json_data.py', 'src/swassh/infrastructure/socket_relay.py', 'src/swassh/infrastructure/relay_connect.py', 'src/swassh/infrastructure/database/migration/encrypted_bytes_v2.py', 'scripts/coverage_child.py', 'scripts/coverage_processes.py', 'scripts/import_policy.py', 'tests/test_runtime_coverage.py', 'tests/runtime_cases/decisions.py', 'tests/test_trace_coverage.py', 'tests/test_extended_coverage.py', 'tests/extended_cases/decisions.py'):
                target = root / missing
                original = target.read_bytes()
                target.unlink()
                with self.subTest(missing=missing), self.assertRaisesRegex(ValueError, "missing deliverable"):
                    script["main"]()
                target.write_bytes(original)
            (root / "src/swassh/application/ports.py").unlink()
            with self.assertRaisesRegex(ValueError, "missing deliverable"):
                script["main"]()
