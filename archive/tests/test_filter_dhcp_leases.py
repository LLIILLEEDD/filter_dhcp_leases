"""Запуск из корня: python3 -B -m unittest discover -s archive/tests -v"""

import datetime
import hashlib
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import filter_dhcp_leases as study


ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "filter_dhcp_leases.py"
DEMO = pathlib.Path(__file__).resolve().parent / "fixtures" / "demo.leases"
DATE = "2026/08/18 10:20:00"


def file_hash(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class CommandLineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = pathlib.Path(self.temp.name)
        self.source = self.directory / "input.leases"
        self.output = self.directory / "output.leases"
        self.source.write_bytes(DEMO.read_bytes())

    def run_cli(self, *extra, defaults=True):
        command = [
            sys.executable, str(SCRIPT), "--input", str(self.source),
        ]
        if "--apply" not in extra:
            command.extend(["--output", str(self.output)])
        if defaults:
            command.extend(["--subnet", "10.201.90.0/24", "--check-date", DATE])
        command.extend(extra)
        return subprocess.run(
            command, cwd=self.directory, capture_output=True,
            text=True, encoding="utf-8", timeout=30,
        )

    def assert_success(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_help_does_not_require_subnet_or_input(self):
        self.source.unlink()
        result = self.run_cli("--help", defaults=False)
        self.assert_success(result)
        self.assertIn("--dry-run", result.stdout)
        self.assertFalse(self.output.exists())

    def test_dry_run_does_not_create_any_file(self):
        before_hash = file_hash(self.source)
        before_names = set(self.directory.iterdir())
        result = self.run_cli("--dry-run")
        self.assert_success(result)
        self.assertEqual(set(self.directory.iterdir()), before_names)
        self.assertEqual(file_hash(self.source), before_hash)
        self.assertIn("Выбрано IP: 3", result.stdout)
        self.assertIn("Удалить блоков: 4", result.stdout)
        self.assertEqual(result.stderr, "")
        self.assertIn("СВОДКА", result.stdout)
        self.assertIn("ВЫБРАННЫЕ IP", result.stdout)
        self.assertNotIn("10.201.90.11", result.stdout)
        self.assertEqual(result.stdout.count("10.201.90.10"), 1)
        self.assertIn("ПРЕДПРОСМОТР", result.stdout)
        self.assertIn("Блоки: 12 -> 8", result.stdout)

    def test_dry_run_does_not_touch_existing_output(self):
        self.output.write_bytes(b"existing output\r\n")
        original_output = self.output.read_bytes()
        result = self.run_cli("--dry-run")
        self.assert_success(result)
        self.assertEqual(self.output.read_bytes(), original_output)

    def test_write_filters_by_latest_state_and_preserves_source(self):
        before_hash = file_hash(self.source)
        result = self.run_cli()
        self.assert_success(result)
        self.assertEqual(file_hash(self.source), before_hash)
        saved = study.read_file(self.output)
        blocks = study.extract_lease_blocks(saved)
        ips = [study.parse_lease(block)["ip"] for block in blocks]
        self.assertEqual(len(blocks), 8)
        self.assertEqual(ips.count("10.201.90.15"), 2)
        for removed in ("10.201.90.10", "10.201.90.16", "10.201.90.18"):
            self.assertNotIn(removed, ips)
        self.assertEqual(set(ips), {
            "10.201.90.11", "10.201.90.12", "10.201.90.13",
            "10.201.90.14", "10.201.90.15", "10.201.90.17", "10.201.91.10",
        })
        self.assertIn("authoring-byte-order little-endian;", saved)
        self.assertIn("Этот комментарий между записями тоже должен сохраниться", saved)
        self.assertIn("Проверка записи: OK", result.stdout)

    def test_threshold_is_strict_and_can_be_changed(self):
        result = self.run_cli("--hours", "48", "--dry-run")
        self.assert_success(result)
        self.assertIn("Выбрано IP: 1", result.stdout)
        self.assertIn("Удалить блоков: 1", result.stdout)

    def test_another_subnet(self):
        result = self.run_cli("--subnet", "10.201.91.0/24", "--dry-run")
        self.assert_success(result)
        self.assertIn("Выбрано IP: 1", result.stdout)
        self.assertIn("10.201.91.10", result.stdout)

    def test_no_matching_subnet_writes_unchanged_copy(self):
        result = self.run_cli("--subnet", "192.0.2.0/24")
        self.assert_success(result)
        self.assertIn("Выбрано IP: 0", result.stdout)
        self.assertEqual(self.output.read_bytes(), self.source.read_bytes())

    def test_verbose_shows_free_and_never_leases(self):
        result = self.run_cli("--dry-run", "--verbose")
        self.assert_success(result)
        rows = [
            [value.strip() for value in line.split("|")]
            for line in result.stdout.splitlines()
            if line.strip().startswith("10.201.90.")
        ]
        self.assertEqual(len(rows), 9)
        by_ip = {row[0]: row for row in rows}
        self.assertEqual(by_ip["10.201.90.11"][1], "free")
        self.assertEqual(by_ip["10.201.90.11"][-1], "оставить")
        self.assertEqual(by_ip["10.201.90.14"][2], "бессрочно")
        self.assertEqual(by_ip["10.201.90.14"][-1], "оставить")
        self.assertEqual(sum(row[-1] == "УДАЛИТЬ" for row in rows), 3)
        self.assertEqual(result.stdout.count("10.201.90.10"), 1)
        self.assertNotIn("ВЫБРАННЫЕ IP", result.stdout)
        self.assertEqual(result.stderr, "")

    def test_missing_subnet_is_argument_error(self):
        result = self.run_cli("--dry-run", defaults=False)
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.output.exists())

    def test_invalid_arguments_do_not_write(self):
        for option, value in [
            ("--subnet", "invalid"), ("--subnet", "10.201.90.1/24"),
            ("--subnet", "2001:db8::/64"),
            ("--check-date", "2026/02/30 10:20:00"), ("--check-date", "never"),
            ("--hours", "0"), ("--hours", "-1"), ("--hours", "1.5"),
        ]:
            with self.subTest(option=option, value=value):
                result = self.run_cli(option, value)
                self.assertEqual(result.returncode, 2)
                self.assertFalse(self.output.exists())

    def test_unknown_option_is_rejected(self):
        result = self.run_cli("--dry")
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.output.exists())

    def test_current_date_is_used_when_not_specified(self):
        before = datetime.datetime.now(datetime.timezone.utc)
        result = self.run_cli("--subnet", "10.201.90.0/24", "--dry-run", defaults=False)
        after = datetime.datetime.now(datetime.timezone.utc)
        self.assert_success(result)
        line = next(line for line in result.stdout.splitlines() if line.strip().startswith("Дата проверки (UTC):"))
        date = datetime.datetime.fromisoformat(line.split(": ", 1)[1])
        self.assertLessEqual(before, date)
        self.assertLessEqual(date, after)

    def test_missing_input_is_runtime_error(self):
        self.source.unlink()
        result = self.run_cli("--dry-run")
        self.assertEqual(result.returncode, 1)
        self.assertIn("Ошибка:", result.stderr)
        self.assertFalse(self.output.exists())

    def test_same_path_is_rejected_without_modifying_source(self):
        before_hash = file_hash(self.source)
        result = self.run_cli("--output", str(self.source))
        self.assertEqual(result.returncode, 1)
        self.assertEqual(file_hash(self.source), before_hash)

    def test_hard_link_to_source_is_rejected(self):
        try:
            os.link(self.source, self.output)
        except OSError as error:
            self.skipTest(str(error))
        before_hash = file_hash(self.source)
        result = self.run_cli()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(file_hash(self.source), before_hash)

    def test_symbolic_link_to_source_is_rejected(self):
        try:
            self.output.symlink_to(self.source)
        except OSError as error:
            self.skipTest(str(error))
        before_hash = file_hash(self.source)
        result = self.run_cli()
        self.assertEqual(result.returncode, 1)
        self.assertEqual(file_hash(self.source), before_hash)

    def test_malformed_input_does_not_overwrite_existing_output(self):
        self.output.write_bytes(b"keep existing output")
        for content in ['lease 10.201.90.10 {', '}', 'lease 10.201.90.10 { uid "unfinished']:
            with self.subTest(content=content):
                self.source.write_text(content, encoding="utf-8")
                result = self.run_cli()
                self.assertEqual(result.returncode, 1)
                self.assertEqual(self.output.read_bytes(), b"keep existing output")

    def test_windows_newlines_preserved(self):
        self.source.write_bytes(DEMO.read_bytes().replace(b"\n", b"\r\n"))
        result = self.run_cli("--subnet", "192.0.2.0/24")
        self.assert_success(result)
        self.assertEqual(self.output.read_bytes(), self.source.read_bytes())


    def test_normal_run_creates_backup_and_persistent_log(self):
        original = self.source.read_bytes()
        result = self.run_cli()
        self.assert_success(result)
        backups = list(self.directory.glob("input.leases.*.bak"))
        self.assertEqual(len(backups), 1)
        self.assertRegex(backups[0].name, r"^input\.leases\.\d{8}_\d{6}\.[0-9a-f]{8}\.bak$")
        self.assertEqual(backups[0].read_bytes(), original)
        log = (self.directory / "filter_dhcp_leases.log").read_text(encoding="utf-8")
        for expected in ("Запуск:", "hours=24", "Выбран IP: 10.201.90.10",
                         "Резервная копия:", "Результат: успешно"):
            self.assertIn(expected, log)
        self.assertRegex(log, r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z INFO")
        self.assertEqual(result.stderr, "")
        self.assertIn("ИТОГ: РЕЗУЛЬТАТ СОХРАНЁН", result.stdout)
        self.assertIn("Журнал:", result.stdout)

    def test_apply_replaces_input_and_preserves_metadata(self):
        original = self.source.read_bytes()
        self.source.chmod(0o640)
        before = self.source.stat()
        result = self.run_cli("--apply")
        self.assert_success(result)
        self.assertFalse(self.output.exists())
        self.assertEqual(len(study.extract_lease_blocks(study.read_file(self.source))), 8)
        backup = next(self.directory.glob("input.leases.*.bak"))
        self.assertEqual(backup.read_bytes(), original)
        after = self.source.stat()
        self.assertEqual(after.st_mode & 0o777, before.st_mode & 0o777)
        self.assertEqual((after.st_uid, after.st_gid), (before.st_uid, before.st_gid))
        self.assertEqual(backup.stat().st_mode & 0o777, before.st_mode & 0o777)
        self.assertEqual(list(self.directory.glob(".*.tmp")), [])

    def test_apply_dry_run_creates_nothing_even_with_custom_paths(self):
        original = self.source.read_bytes()
        before = set(self.directory.iterdir())
        result = self.run_cli(
            "--apply", "--dry-run", "--backup-dir", str(self.directory / "backups"),
            "--log-file", str(self.directory / "not-created.log"),
        )
        self.assert_success(result)
        self.assertEqual(self.source.read_bytes(), original)
        self.assertEqual(set(self.directory.iterdir()), before)
        self.assertIn("ИТОГ: ПРЕДПРОСМОТР ЗАВЕРШЁН", result.stdout)
        self.assertIn("ЗАМЕНА ИСХОДНИКА", result.stdout)
        self.assertEqual(result.stderr, "")

    def test_apply_cannot_be_combined_with_output(self):
        original = self.source.read_bytes()
        result = self.run_cli("--apply", "--output", str(self.output))
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.source.read_bytes(), original)
        self.assertFalse(self.output.exists())

    def test_backups_are_unique_and_log_is_appended(self):
        original = self.source.read_bytes()
        self.assert_success(self.run_cli())
        logfile = self.directory / "filter_dhcp_leases.log"
        first_log = logfile.read_bytes()
        first_backup = next(self.directory.glob("input.leases.*.bak"))
        self.assert_success(self.run_cli())
        backups = list(self.directory.glob("input.leases.*.bak"))
        self.assertEqual(len(backups), 2)
        self.assertEqual(first_backup.read_bytes(), original)
        self.assertTrue(all(path.read_bytes() == original for path in backups))
        self.assertTrue(logfile.read_bytes().startswith(first_log))
        self.assertGreater(len(logfile.read_bytes()), len(first_log))

    def test_custom_backup_directory_and_log_path(self):
        directory = self.directory / "backups"
        log = self.directory / "custom.log"
        result = self.run_cli("--backup-dir", str(directory), "--log-file", str(log))
        self.assert_success(result)
        self.assertEqual(len(list(directory.glob("input.leases.*.bak"))), 1)
        self.assertTrue(log.exists())
        self.assertFalse((self.directory / "filter_dhcp_leases.log").exists())

    def test_log_cannot_alias_input_or_output(self):
        self.output.write_bytes(b"existing")
        original = self.source.read_bytes()
        for path in (self.source, self.output):
            with self.subTest(path=path):
                result = self.run_cli("--log-file", str(path))
                self.assertEqual(result.returncode, 1)
                self.assertEqual(self.source.read_bytes(), original)
                self.assertEqual(self.output.read_bytes(), b"existing")
        alias = self.directory / "alias.log"
        os.link(self.source, alias)
        result = self.run_cli("--log-file", str(alias))
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.source.read_bytes(), original)

    def test_runtime_error_is_logged(self):
        self.source.write_text("lease 10.201.90.10 {", encoding="utf-8")
        result = self.run_cli()
        self.assertEqual(result.returncode, 1)
        log = (self.directory / "filter_dhcp_leases.log").read_text(encoding="utf-8")
        self.assertIn("ERROR Ошибка:", log)
        self.assertIn("Traceback", log)
        self.assertNotIn("Traceback", result.stderr)
        self.assertIn("Подробности в журнале:", result.stderr)
        self.assertNotIn("ИТОГ: РЕЗУЛЬТАТ СОХРАНЁН", result.stdout)
        self.assertIn("незавершённый блок", log)
        self.assertFalse(list(self.directory.glob("*.bak")))
        self.assertFalse(self.output.exists())

    def test_apply_rejects_symbolic_and_hard_links(self):
        original = self.source.read_bytes()
        alias = self.directory / "linked.leases"
        for symbolic in (True, False):
            with self.subTest(symbolic=symbolic):
                if symbolic:
                    alias.symlink_to(self.source)
                else:
                    os.link(self.source, alias)
                try:
                    result = subprocess.run(
                        [sys.executable, str(SCRIPT), "--input", str(alias),
                         "--subnet", "10.201.90.0/24", "--apply"],
                        cwd=self.directory, capture_output=True, text=True,
                        encoding="utf-8", timeout=30,
                    )
                    self.assertEqual(result.returncode, 1)
                    self.assertEqual(self.source.read_bytes(), original)
                finally:
                    alias.unlink()


class SafeApplyFailureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = pathlib.Path(self.temp.name)
        self.source = self.directory / "input.leases"
        self.source.write_bytes(DEMO.read_bytes())
        self.original = self.source.read_bytes()
        self.blocks = study.extract_lease_blocks(study.read_file(self.source))
        self.ips = {"10.201.90.10"}
        self.content = study.build_filtered_content(
            study.read_file(self.source), self.blocks, self.ips,
        )
        self.signature = study.source_signature(self.source)
        import logging
        self.logger = logging.getLogger("filter_dhcp_leases.tests")

    def apply(self):
        return study.apply_safely(
            self.source, self.content, self.blocks, self.ips,
            self.original, self.signature, None, self.logger,
        )

    def assert_unchanged_and_clean(self):
        self.assertEqual(self.source.read_bytes(), self.original)
        self.assertEqual(list(self.directory.glob(".*.tmp")), [])

    def test_failed_backup_never_replaces_input(self):
        with mock.patch.object(study, "create_backup", side_effect=OSError("backup failed")):
            with self.assertRaises(OSError):
                self.apply()
        self.assert_unchanged_and_clean()

    def test_failed_replace_preserves_input_and_backup(self):
        with mock.patch.object(study.os, "replace", side_effect=OSError("replace failed")):
            with self.assertRaises(OSError):
                self.apply()
        self.assert_unchanged_and_clean()
        backup = next(self.directory.glob("*.bak"))
        self.assertEqual(backup.read_bytes(), self.original)

    def test_disk_verification_failure_never_replaces_input(self):
        with mock.patch.object(study, "read_file", return_value="corrupt"):
            with self.assertRaises(ValueError):
                self.apply()
        self.assert_unchanged_and_clean()
        self.assertFalse(list(self.directory.glob("*.bak")))

    def test_invalid_filtered_content_never_replaces_input(self):
        self.content = "lease 10.201.90.99 {"
        with self.assertRaises(ValueError):
            self.apply()
        self.assert_unchanged_and_clean()

    def test_source_change_after_backup_cancels_replace(self):
        create_backup = study.create_backup
        changed = self.original + b"\n# external update\n"
        def backup_then_change(*args, **kwargs):
            backup = create_backup(*args, **kwargs)
            self.source.write_bytes(changed)
            return backup
        with mock.patch.object(study, "create_backup", side_effect=backup_then_change):
            with self.assertRaisesRegex(ValueError, "изменился"):
                self.apply()
        self.assertEqual(self.source.read_bytes(), changed)
        self.assertEqual(list(self.directory.glob(".*.tmp")), [])

    def test_source_change_before_apply_is_rejected(self):
        self.source.write_bytes(self.original + b"\n")
        with mock.patch.object(study.os, "replace") as replace:
            with self.assertRaisesRegex(ValueError, "изменился"):
                self.apply()
            replace.assert_not_called()
        self.assertFalse(list(self.directory.glob("*.bak")))
        self.assertEqual(list(self.directory.glob(".*.tmp")), [])

    def test_backup_partial_copy_is_cleaned_up(self):
        with mock.patch.object(study.shutil, "copyfileobj", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                study.create_backup(self.source)
        self.assert_unchanged_and_clean()
        self.assertFalse(list(self.directory.glob("*.bak")))

    def test_backup_collision_does_not_overwrite_existing_copy(self):
        # Разные UUID с одинаковыми первыми 8 символами дают коллизию имени.
        with mock.patch.object(study.datetime, "datetime") as clock:
            clock.now.return_value.strftime.return_value = "20261016_112352"
            with mock.patch.object(study.uuid, "uuid4", side_effect=[
                mock.Mock(hex="ff147766" + "0" * 24),
                mock.Mock(hex="ff147766" + "1" * 24),
                mock.Mock(hex="a3f91c2d" + "2" * 24),
            ]) as make_uuid:
                first = study.create_backup(self.source)
                second = study.create_backup(self.source)
        self.assertEqual(make_uuid.call_count, 3)
        self.assertEqual(first.name, "input.leases.20261016_112352.ff147766.bak")
        self.assertEqual(second.name, "input.leases.20261016_112352.a3f91c2d.bak")
        self.assertEqual(first.read_bytes(), self.original)
        self.assertEqual(second.read_bytes(), self.original)


class BlockExtractionTests(unittest.TestCase):
    def test_quotes_comments_escapes_and_nested_blocks(self):
        block = r'''lease 10.201.90.10 {
  uid "\001}2";
  set note = "{ # escaped quote \" and backslash \\";
  # } { }
  on expiry { set note = "}"; }
}'''
        other = 'lease 10.201.90.11 { binding state free; }'
        between = ' # retain comment }\n'
        content = '# lease 192.0.2.1 {\n' + block + between + other
        self.assertEqual(study.extract_lease_blocks(content), [block, other])
        self.assertEqual(
            study.build_filtered_content(content, [block, other], {"10.201.90.10"}),
            '# lease 192.0.2.1 {\n' + between + other,
        )

    def test_non_lease_blocks_are_retained(self):
        content = 'group { set note = "}"; }\n# trailing {\n'
        blocks = study.extract_lease_blocks(content)
        self.assertEqual(blocks, [])
        self.assertEqual(study.build_filtered_content(content, blocks, set()), content)

    def test_two_leases_on_one_line_have_separate_boundaries(self):
        first = 'lease 10.201.90.10 { }'
        second = 'lease 10.201.90.11 { }'
        self.assertEqual(study.extract_lease_blocks(first + ' ' + second), [first, second])


class FilteredContentTests(unittest.TestCase):
    def filter(self, content, ips):
        blocks = study.extract_lease_blocks(content)
        result = study.build_filtered_content(content, blocks, ips)
        study.verify_result(blocks, result, ips)
        return result

    def test_consecutive_removed_blocks_leave_no_empty_lines(self):
        for newline in ("\n", "\r\n", "\r"):
            with self.subTest(newline=repr(newline)):
                first = newline.join(("lease 192.0.2.1 {", "  # keep", "", "}"))
                last = "lease 192.0.2.4 { }"
                removed = [
                    "  lease 192.0.2.2 {" + newline + "  } \t",
                    "\tlease 192.0.2.3 { }",
                ]
                content = newline.join([first, *removed, last]) + newline
                self.assertEqual(
                    self.filter(content, {"192.0.2.2", "192.0.2.3"}),
                    first + newline + last + newline,
                )

    def test_comments_and_existing_blank_lines_are_preserved(self):
        content = (
            "# header\n\nlease 192.0.2.1 { }\n\n"
            "# comment before\n  lease 192.0.2.2 { }\n"
            "# comment after\n\nlease 192.0.2.3 { }\n"
        )
        self.assertEqual(
            self.filter(content, {"192.0.2.2"}),
            "# header\n\nlease 192.0.2.1 { }\n\n"
            "# comment before\n# comment after\n\nlease 192.0.2.3 { }\n",
        )

    def test_comment_after_closing_brace_is_preserved(self):
        content = "lease 192.0.2.1 { } # keep comment }\r\nlease 192.0.2.2 { }\r\n"
        self.assertEqual(
            self.filter(content, {"192.0.2.1"}),
            " # keep comment }\r\nlease 192.0.2.2 { }\r\n",
        )

    def test_multiple_blocks_on_one_line_keep_other_blocks(self):
        content = "lease 192.0.2.1 { } lease 192.0.2.2 { } lease 192.0.2.3 { }\n"
        self.assertEqual(
            self.filter(content, {"192.0.2.2"}),
            "lease 192.0.2.1 { }  lease 192.0.2.3 { }\n",
        )

    def test_last_block_without_final_newline_is_removed_with_indent(self):
        content = "lease 192.0.2.1 { }\r\n\tlease 192.0.2.2 { }  "
        self.assertEqual(
            self.filter(content, {"192.0.2.2"}), "lease 192.0.2.1 { }\r\n",
        )

    def test_all_blocks_can_be_removed_without_leaving_line_breaks(self):
        content = "lease 192.0.2.1 { }\nlease 192.0.2.2 { }\n"
        self.assertEqual(self.filter(content, {"192.0.2.1", "192.0.2.2"}), "")

    def test_no_selected_ips_preserves_original_text(self):
        content = "\n# header\r\n  lease 192.0.2.1 { }\r\n\r\n# tail\r\n"
        self.assertEqual(self.filter(content, set()), content)


if __name__ == "__main__":
    unittest.main()
