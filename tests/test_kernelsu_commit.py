"""Regression tests for pinned SukiSU revisions and SUSFS compatibility."""

import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / ".github/workflows/scripts"))
with patch("urllib.request.urlopen", return_value=io.BytesIO(b'#define SUSFS_VERSION "test"')):
    from kernel_builder import KernelBuilder


BUILTIN_COMMIT = "b20dee702035af09cb2ecb5f35443bbc1747f3e6"
MAIN_COMMIT = "85eb4a95b8a61d756ecf53b9c5785e48e1b15039"
SUPPORTED_KCONFIG = '''menu "KernelSU"
config KSU
\tbool "KernelSU function support"
config KPM
\tbool "Enable SukiSU KPM"
config KSU_SUSFS
\tbool "KernelSU addon - SUSFS"
\tdepends on KSU
endmenu
'''


class KernelSUCommitTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(prefix=".test-ksu-", dir=REPO_ROOT)
        self.addCleanup(self.temp_dir.cleanup)
        self.work_dir = Path(self.temp_dir.name)
        self.ksu_dir = self.work_dir / "KernelSU"
        self.kconfig = self.ksu_dir / "kernel/Kconfig"
        self.kconfig.parent.mkdir(parents=True)
        self.kconfig.write_text(SUPPORTED_KCONFIG, encoding="utf-8")
        self.setup_file = self.work_dir / ".ksu-setup.sh"

    def make_builder(self, commit=None, expected=BUILTIN_COMMIT, actual=BUILTIN_COMMIT):
        builder = object.__new__(KernelBuilder)
        builder.config = SimpleNamespace(kernelsu_commit=commit)
        builder.work_dir = self.work_dir
        builder._chdir = Mock()
        builder._run_cmd = Mock(side_effect=[
            subprocess.CompletedProcess("download", 0),
            subprocess.CompletedProcess("setup", 0),
            subprocess.CompletedProcess("resolve", 0, stdout=expected + "\n"),
            subprocess.CompletedProcess("checkout", 0),
            subprocess.CompletedProcess("head", 0, stdout=actual + "\n"),
        ])
        return builder

    def commands(self, builder):
        return [call.args[0] for call in builder._run_cmd.call_args_list]

    def test_empty_commit_resolves_remote_builtin(self):
        for commit in (None, "", "  "):
            with self.subTest(commit=commit):
                builder = self.make_builder(commit)
                builder.add_kernelsu()
                commands = self.commands(builder)
                self.assertEqual(len(commands), 5)
                self.assertEqual(commands[1], f'bash "{self.setup_file}" "builtin"')
                self.assertIn('rev-parse --verify "refs/remotes/origin/builtin^{commit}"', commands[2])
                self.assertIn(f'checkout --detach "{BUILTIN_COMMIT}"', commands[3])
                self.assertTrue(commands[4].endswith("rev-parse HEAD"))

    def test_full_commit_is_passed_to_setup_and_verified(self):
        builder = self.make_builder(BUILTIN_COMMIT)
        with patch.object(KernelBuilder, "_validate_kernelsu_susfs") as validate:
            builder.add_kernelsu()
        commands = self.commands(builder)
        self.assertEqual(commands[1], f'bash "{self.setup_file}" "{BUILTIN_COMMIT}"')
        self.assertIn(f'rev-parse --verify "{BUILTIN_COMMIT}^{{commit}}"', commands[2])
        validate.assert_called_once_with(self.ksu_dir, BUILTIN_COMMIT)

    def test_short_commit_is_resolved_to_full_hash(self):
        short_commit = BUILTIN_COMMIT[:8]
        builder = self.make_builder(short_commit)
        builder.add_kernelsu()
        commands = self.commands(builder)
        self.assertEqual(commands[1], f'bash "{self.setup_file}" "{short_commit}"')
        self.assertIn(f'rev-parse --verify "{short_commit}^{{commit}}"', commands[2])
        self.assertIn(f'checkout --detach "{BUILTIN_COMMIT}"', commands[3])
        self.assertNotIn(f"/{short_commit}/kernel/setup.sh", commands[0])

    def test_commit_whitespace_is_trimmed(self):
        builder = self.make_builder(f"  {BUILTIN_COMMIT}\n")
        builder.add_kernelsu()
        self.assertEqual(self.commands(builder)[1], f'bash "{self.setup_file}" "{BUILTIN_COMMIT}"')

    def test_uppercase_hash_is_resolved_by_git(self):
        builder = self.make_builder(BUILTIN_COMMIT[:8].upper())
        builder.add_kernelsu()
        self.assertIn(f'checkout --detach "{BUILTIN_COMMIT}"', self.commands(builder)[3])

    def test_invalid_hash_is_rejected_before_commands(self):
        for commit in ("builtin", "main", "123456", "a" * 41, "g" * 40, "abcdef0; echo bad", "abc\ndef0"):
            with self.subTest(commit=commit):
                builder = self.make_builder(commit)
                with self.assertRaisesRegex(ValueError, "7-40.*hexadecimal"):
                    builder.add_kernelsu()
                builder._run_cmd.assert_not_called()
                builder._chdir.assert_not_called()

    def test_setup_and_git_commands_check_exit_status(self):
        builder = self.make_builder()
        builder.add_kernelsu()
        self.assertIn("curl -fLSs --retry 3", self.commands(builder)[0])
        for call in builder._run_cmd.call_args_list:
            self.assertTrue(call.kwargs.get("check", True))
        self.assertTrue(builder._run_cmd.call_args_list[2].kwargs["capture_output"])
        self.assertTrue(builder._run_cmd.call_args_list[4].kwargs["capture_output"])

    def test_setup_script_is_cleaned_after_success(self):
        self.setup_file.write_text("#!/bin/sh\n", encoding="utf-8")
        self.make_builder().add_kernelsu()
        self.assertFalse(self.setup_file.exists())

    def test_download_or_setup_failure_is_propagated_and_cleaned(self):
        for stage in (1, 2):
            with self.subTest(stage=stage):
                self.setup_file.write_text("#!/bin/sh\n", encoding="utf-8")
                builder = self.make_builder()
                builder._run_cmd.side_effect = (
                    [subprocess.CompletedProcess("download", 0)] * (stage - 1)
                    + [subprocess.CalledProcessError(1, "setup")]
                )
                with self.assertRaises(subprocess.CalledProcessError):
                    builder.add_kernelsu()
                self.assertEqual(builder._run_cmd.call_count, stage)
                self.assertFalse(self.setup_file.exists())

    def test_unresolvable_commit_fails_before_checkout(self):
        builder = self.make_builder("abcdef0")
        builder._run_cmd.side_effect = [
            subprocess.CompletedProcess("download", 0),
            subprocess.CompletedProcess("setup", 0),
            subprocess.CalledProcessError(128, "rev-parse"),
        ]
        with self.assertRaises(subprocess.CalledProcessError):
            builder.add_kernelsu()
        self.assertEqual(builder._run_cmd.call_count, 3)

    def test_checkout_failure_is_propagated(self):
        builder = self.make_builder(BUILTIN_COMMIT)
        builder._run_cmd.side_effect = [
            subprocess.CompletedProcess("download", 0),
            subprocess.CompletedProcess("setup", 0),
            subprocess.CompletedProcess("resolve", 0, stdout=BUILTIN_COMMIT + "\n"),
            subprocess.CalledProcessError(128, "checkout"),
        ]
        with self.assertRaises(subprocess.CalledProcessError):
            builder.add_kernelsu()
        self.assertEqual(builder._run_cmd.call_count, 4)

    def test_fallback_to_different_head_is_rejected(self):
        builder = self.make_builder(BUILTIN_COMMIT, actual=MAIN_COMMIT)
        with patch.object(KernelBuilder, "_validate_kernelsu_susfs") as validate:
            with self.assertRaisesRegex(RuntimeError, "SukiSU revision mismatch") as error:
                builder.add_kernelsu()
        self.assertIn(BUILTIN_COMMIT, str(error.exception))
        self.assertIn(MAIN_COMMIT, str(error.exception))
        validate.assert_not_called()

    def test_resolved_revision_must_be_full_hash(self):
        for resolved in ("", "builtin", "abcdef0", "z" * 40):
            with self.subTest(resolved=resolved):
                builder = self.make_builder(BUILTIN_COMMIT, expected=resolved, actual=resolved)
                with self.assertRaisesRegex(RuntimeError, "Invalid resolved SukiSU commit"):
                    builder.add_kernelsu()
                self.assertEqual(builder._run_cmd.call_count, 3)

    def test_mainline_commit_with_kpm_requires_susfs(self):
        self.kconfig.write_text('''menu "KernelSU"
config KSU
\ttristate "KernelSU function support"
config KPM
\tbool "Enable SukiSU KPM"
\tdepends on KSU && 64BIT
endmenu
''', encoding="utf-8")
        builder = self.make_builder(MAIN_COMMIT, expected=MAIN_COMMIT, actual=MAIN_COMMIT)
        with self.assertRaisesRegex(RuntimeError, f"{MAIN_COMMIT}.*CONFIG_KSU_SUSFS") as error:
            builder.add_kernelsu()
        self.assertIn("commits/builtin/", str(error.exception))
        self.assertIn("leave kernelsu_commit empty", str(error.exception))

    def test_missing_kconfig_reports_commit_and_path(self):
        self.kconfig.unlink()
        with self.assertRaisesRegex(RuntimeError, "Kconfig") as error:
            KernelBuilder._validate_kernelsu_susfs(self.ksu_dir, MAIN_COMMIT)
        self.assertIn(MAIN_COMMIT, str(error.exception))

    def test_comments_and_suboptions_do_not_declare_susfs(self):
        for content in (
            "# config KSU_SUSFS\n",
            "config KSU_SUSFS_SUS_PATH\n\tbool\n",
            "config KSU_SUSFS_ENABLE_LOG\n\tbool\n",
            'config KSU\n\tbool "config KSU_SUSFS"\n',
            "CONFIG_KSU_SUSFS=y\n",
        ):
            with self.subTest(content=content):
                self.kconfig.write_text(content, encoding="utf-8")
                with self.assertRaisesRegex(RuntimeError, "lacks CONFIG_KSU_SUSFS"):
                    KernelBuilder._validate_kernelsu_susfs(self.ksu_dir, MAIN_COMMIT)

    def test_exact_config_and_menuconfig_are_supported(self):
        for declaration in ("config KSU_SUSFS", "menuconfig KSU_SUSFS", "  config\tKSU_SUSFS  "):
            with self.subTest(declaration=declaration):
                self.kconfig.write_text(declaration + '\n\tbool "SUSFS"\n', encoding="utf-8")
                KernelBuilder._validate_kernelsu_susfs(self.ksu_dir, BUILTIN_COMMIT)


if __name__ == "__main__":
    unittest.main()
