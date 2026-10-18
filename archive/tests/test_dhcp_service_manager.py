"""Проверки lifecycle без root, systemd-изменений и установки DHCP."""

import contextlib
import io
import logging
import os
import pathlib
import subprocess
import tempfile
import unittest
from unittest import mock

import filter_dhcp_leases as study
import dhcp_service_manager as service


ROOT = pathlib.Path(__file__).resolve().parents[2]
DEMO = pathlib.Path(__file__).resolve().parent / "fixtures" / "demo.leases"
DATE = "2026/08/18 10:20:00"


class ManagedServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = pathlib.Path(self.temp.name)
        self.source = self.directory / "input.leases"
        self.source.write_bytes(DEMO.read_bytes())
        self.original = self.source.read_bytes()
        self.config = self.directory / "dhcpd.conf"
        self.config.write_text("# lab\n", encoding="utf-8")
        self.binary = self.directory / "dhcpd"
        self.binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        self.binary.chmod(0o700)
        self.log = self.directory / "filter.log"
        self.events = []
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(service.os, "geteuid", return_value=0))
        self.stack.enter_context(mock.patch.object(service.shutil, "which", return_value="/usr/bin/systemctl"))
        self.state = self.stack.enter_context(mock.patch.object(service, "service_state", return_value={
            "LoadState": "loaded", "ActiveState": "active", "SubState": "running", "MainPID": "123",
        }))
        self.binding = self.stack.enter_context(mock.patch.object(service, "check_process_binding"))
        self.config_check = self.stack.enter_context(mock.patch.object(
            service, "validate_config", side_effect=lambda *args: self.events.append("config"),
        ))
        self.validator = self.stack.enter_context(mock.patch.object(
            service, "validate_lease_file", side_effect=self.validate,
        ))
        # Импортированная в main функция должна использовать ту же тестовую проверку.
        self.stack.enter_context(mock.patch.object(study, "validate_lease_file", self.validator))
        self.stop = self.stack.enter_context(mock.patch.object(
            service, "stop_service", side_effect=lambda *args: self.events.append("stop"),
        ))
        self.start = self.stack.enter_context(mock.patch.object(
            service, "start_service", side_effect=lambda *args: self.events.append("start"),
        ))

    def validate(self, args, path, logger):
        self.events.append("leases-original" if path == self.source else "leases-temporary")

    def argv(self):
        return [
            "-i", str(self.source), "-s", "10.201.90.0/24", "--check-date", DATE,
            "--apply", "--manage-service", "--service", "dhcp-lab.service",
            "--dhcpd", str(self.binary), "--dhcp-config", str(self.config),
            "--log-file", str(self.log),
        ]

    def run_main(self, *extra):
        output, errors = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            code = study.main([*self.argv(), *extra])
        return code, output.getvalue(), errors.getvalue()

    def test_success_stops_before_analysis_and_starts_after_replace(self):
        code, output, errors = self.run_main()
        self.assertEqual(code, 0, errors)
        self.assertEqual(self.events, ["config", "stop", "leases-original", "leases-temporary", "start"])
        self.assertEqual(len(study.extract_lease_blocks(study.read_file(self.source))), 8)
        self.assertIn("active/running, проверена", output)
        self.assertEqual(errors, "")
        self.assertEqual(next(self.directory.glob("*.bak")).read_bytes(), self.original)

    def test_final_flush_at_stop_is_included_in_analysis_and_backup(self):
        flushed = self.original + b"\nlease 10.201.90.10 {\n  binding state free;\n}\n"
        def stop_and_flush(*args):
            self.events.append("stop")
            self.source.write_bytes(flushed)
        self.stop.side_effect = stop_and_flush
        code, output, errors = self.run_main()
        self.assertEqual(code, 0, errors)
        self.assertIn("Выбрано IP: 2", output)
        self.assertIn("lease 10.201.90.10", study.read_file(self.source))
        self.assertEqual(next(self.directory.glob("*.bak")).read_bytes(), flushed)

    def test_dry_run_never_touches_service_or_creates_files(self):
        before = set(self.directory.iterdir())
        code, output, errors = self.run_main("--dry-run")
        self.assertEqual(code, 0, errors)
        self.assertEqual(self.source.read_bytes(), self.original)
        self.assertEqual(set(self.directory.iterdir()), before)
        self.state.assert_not_called()
        self.stop.assert_not_called()
        self.start.assert_not_called()
        self.validator.assert_not_called()
        self.assertIn("ПРЕДПРОСМОТР", output)

    def test_bad_configuration_does_not_stop_service(self):
        self.config_check.side_effect = RuntimeError("bad config")
        code, _, _ = self.run_main()
        self.assertEqual(code, 1)
        self.stop.assert_not_called()
        self.start.assert_not_called()
        self.assertEqual(self.source.read_bytes(), self.original)

    def test_wrong_process_binding_does_not_stop_service(self):
        self.binding.side_effect = RuntimeError("wrong lease file")
        code, _, _ = self.run_main()
        self.assertEqual(code, 1)
        self.stop.assert_not_called()
        self.assertEqual(self.source.read_bytes(), self.original)

    def test_inactive_service_is_rejected_without_start(self):
        self.state.return_value = {"LoadState": "loaded", "ActiveState": "inactive", "MainPID": "0"}
        self.assertEqual(self.run_main()[0], 1)
        self.stop.assert_not_called()
        self.start.assert_not_called()

    def test_failed_stop_never_replaces_database_and_attempts_resume(self):
        self.stop.side_effect = RuntimeError("stop timeout")
        self.assertEqual(self.run_main()[0], 1)
        self.start.assert_called_once()
        self.validator.assert_not_called()
        self.assertEqual(self.source.read_bytes(), self.original)

    def test_invalid_original_database_resumes_without_changes(self):
        self.validator.side_effect = RuntimeError("invalid original")
        self.assertEqual(self.run_main()[0], 1)
        self.start.assert_called_once()
        self.assertEqual(self.source.read_bytes(), self.original)
        self.assertFalse(list(self.directory.glob("*.bak")))

    def test_invalid_temporary_database_resumes_without_replacing(self):
        def validate(args, path, logger):
            if path != self.source:
                raise RuntimeError("invalid temporary")
        self.validator.side_effect = validate
        code, output, _ = self.run_main()
        self.assertEqual(code, 1)
        self.start.assert_called_once()
        self.assertEqual(self.source.read_bytes(), self.original)
        self.assertFalse(list(self.directory.glob("*.bak")))
        self.assertFalse(list(self.directory.glob(".*.tmp")))
        self.assertNotIn("ИТОГ: ИСХОДНИК ОБНОВЛЁН", output)

    def test_failed_backup_never_replaces_and_resumes_service(self):
        with mock.patch.object(study, "create_backup", side_effect=OSError("disk full")):
            self.assertEqual(self.run_main()[0], 1)
        self.assertEqual(self.source.read_bytes(), self.original)
        self.start.assert_called_once()

    def test_failed_start_restores_original_and_starts_again(self):
        self.start.side_effect = [RuntimeError("new start failed"), None]
        code, output, errors = self.run_main()
        self.assertEqual(code, 1)
        self.assertEqual(self.start.call_count, 2)
        self.assertEqual(self.stop.call_count, 2)
        self.assertEqual(self.source.read_bytes(), self.original)
        self.assertEqual(len(list(self.directory.glob("*.bak"))), 2)
        self.assertNotIn("ИТОГ: ИСХОДНИК ОБНОВЛЁН", output)
        self.assertIn("восстановлена", errors)

    def test_exception_after_replace_also_restores_original(self):
        apply = study.apply_safely
        def replace_then_fail(*args, **kwargs):
            apply(*args, **kwargs)
            raise OSError("failure after replace")
        with mock.patch.object(study, "apply_safely", side_effect=replace_then_fail):
            self.assertEqual(self.run_main()[0], 1)
        self.assertEqual(self.source.read_bytes(), self.original)
        self.assertEqual(self.stop.call_count, 2)
        self.start.assert_called_once()

    def test_directory_sync_failure_after_replace_restores_original(self):
        # Замена уже произошла, но fsync каталога может завершиться ошибкой.
        # Отмеченная замена должна запустить восстановление, а не только start.
        with mock.patch.object(study, "sync_directory", side_effect=OSError("directory fsync failed")):
            code, output, errors = self.run_main()
        self.assertEqual(code, 1)
        self.assertEqual(self.source.read_bytes(), self.original)
        self.assertEqual(self.stop.call_count, 2)
        self.start.assert_called_once()
        self.assertEqual(len(list(self.directory.glob("*.bak"))), 2)
        self.assertIn("Файл уже заменён", errors)
        self.assertNotIn("ИТОГ: ИСХОДНИК ОБНОВЛЁН", output)

    def test_failed_recovery_is_explicit_and_never_reports_success(self):
        self.start.side_effect = RuntimeError("cannot start")
        code, output, errors = self.run_main()
        self.assertEqual(code, 1)
        self.assertIn("ВОССТАНОВЛЕНИЕ НЕ УДАЛОСЬ", errors)
        self.assertNotIn("ИТОГ: ИСХОДНИК ОБНОВЛЁН", output)
        self.assertEqual(self.source.read_bytes(), self.original)

    def test_root_is_required_only_for_real_managed_apply(self):
        with mock.patch.object(service.os, "geteuid", return_value=1000):
            code, _, errors = self.run_main()
        self.assertEqual(code, 1)
        self.assertIn("root", errors)
        self.stop.assert_not_called()

    def test_manage_service_requires_apply_and_timeout_is_bounded(self):
        for arguments in (
            ["-s", "10.201.90.0/24", "--manage-service"],
            ["-s", "10.201.90.0/24", "--service-timeout", "0"],
            ["-s", "10.201.90.0/24", "--service-timeout", "301"],
        ):
            with self.subTest(arguments=arguments), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    study.parse_arguments(arguments)
                self.assertEqual(error.exception.code, 2)


class CommandAndLockTests(unittest.TestCase):
    def setUp(self):
        self.logger = logging.getLogger("service-tests")
        self.logger.addHandler(logging.NullHandler())

    def test_subprocess_receives_argument_list_without_shell(self):
        result = subprocess.CompletedProcess([], 0, "ok", "")
        with mock.patch.object(service.subprocess, "run", return_value=result) as run:
            self.assertEqual(service.run_command(["tool", "file with spaces"], self.logger, 10), "ok")
        self.assertEqual(run.call_args.args[0], ["tool", "file with spaces"])
        self.assertNotIn("shell", run.call_args.kwargs)
        self.assertEqual(run.call_args.kwargs["timeout"], 10)

    def test_command_failure_and_timeout_are_runtime_errors(self):
        for effect in (
            subprocess.CompletedProcess([], 1, "", "invalid leases"),
            subprocess.TimeoutExpired(["dhcpd"], 1),
        ):
            with self.subTest(effect=effect):
                options = {"side_effect": effect} if isinstance(effect, Exception) else {"return_value": effect}
                with mock.patch.object(service.subprocess, "run", **options):
                    with self.assertRaises(RuntimeError):
                        service.run_command(["dhcpd"], self.logger, 1)

    def test_lock_excludes_second_filter_and_survives_file_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "input.leases"
            path.write_bytes(b"old")
            with service.service_lock(path):
                replacement = path.with_suffix(".new")
                replacement.write_bytes(b"new")
                os.replace(replacement, path)
                with self.assertRaisesRegex(RuntimeError, "уже обрабатывается"):
                    with service.service_lock(path):
                        self.fail("second lock acquired")
            with service.service_lock(path):
                pass

    def test_lock_does_not_follow_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "input.leases"
            target = pathlib.Path(directory) / "keep"
            target.write_bytes(b"keep")
            lock = path.parent / f".{path.name}.dhcp-filter.lock"
            lock.symlink_to(target)
            with self.assertRaises(OSError):
                with service.service_lock(path):
                    self.fail("symlink lock acquired")
            self.assertEqual(target.read_bytes(), b"keep")

    def test_stop_must_confirm_no_main_pid(self):
        args = mock.Mock(systemctl="/bin/systemctl", service="test.service", service_timeout=5)
        with mock.patch.object(service, "run_command"), mock.patch.object(
            service, "service_state", return_value={"ActiveState": "active", "MainPID": "42"},
        ):
            with self.assertRaisesRegex(RuntimeError, "запись запрещена"):
                service.stop_service(args, self.logger)

    def test_start_checks_process_and_running_state_repeatedly(self):
        args = mock.Mock(systemctl="/bin/systemctl", service="test.service", service_timeout=5)
        active = {"ActiveState": "active", "SubState": "running", "MainPID": "42"}
        with mock.patch.object(service, "run_command"), mock.patch.object(
            service, "service_state", side_effect=[active, {"ActiveState": "failed"}],
        ), mock.patch.object(service, "check_process_binding"), mock.patch.object(service.time, "sleep"):
            with self.assertRaisesRegex(RuntimeError, "active/running"):
                service.start_service(args, self.logger)

    def test_process_binding_requires_matching_explicit_paths_and_ipv4(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            binary, config, leases = [root / name for name in ("dhcpd", "conf", "leases")]
            for path in (binary, config, leases):
                path.touch()
            args = mock.Mock(dhcpd=binary, dhcp_config=config, input=leases)
            command = [str(binary), "-4", "-cf", str(config), "-lf", str(leases)]
            # Подменяем только чтение /proc; пути конфигурации разрешаются реально.
            real_resolve = pathlib.Path.resolve
            def resolve(path, *a, **kw):
                if str(path) == "/proc/123/exe":
                    return binary
                return real_resolve(path, *a, **kw)
            for values, good in (
                (command, True),
                (command[:-2], False),
                ([*command, "-6"], False),
                ([*command[:-1], str(root / "wrong")], False),
            ):
                with self.subTest(command=values), mock.patch.object(
                    pathlib.Path, "resolve", resolve,
                ), mock.patch.object(pathlib.Path, "read_bytes", return_value=b"\0".join(os.fsencode(value) for value in values)):
                    if good:
                        service.check_process_binding(args, {"MainPID": "123"})
                    else:
                        with self.assertRaises(RuntimeError):
                            service.check_process_binding(args, {"MainPID": "123"})


if __name__ == "__main__":
    unittest.main()
