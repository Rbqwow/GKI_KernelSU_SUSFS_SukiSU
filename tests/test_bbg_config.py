"""Regression tests for Baseband-guard configuration integration."""

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


KCONFIG_PREFIX = '''menu "Security options"

config LSM_MMAP_MIN_ADDR
\tint "Low address space for LSM"
\tdefault 32768 if ARM || (ARM64 && COMPAT)
\tdefault 65536
\thelp
\t  Preserve this unrelated security configuration.

source "security/selinux/Kconfig"

'''
LSM_CONFIG = '''config LSM
\tstring "Ordered list of enabled LSMs"
\tdefault "lockdown,yama,smack,selinux,bpf" if DEFAULT_SECURITY_SMACK
\tdefault "lockdown,yama,apparmor,selinux,bpf" if DEFAULT_SECURITY_APPARMOR
\tdefault "lockdown,yama,tomoyo,bpf" if DEFAULT_SECURITY_TOMOYO
\tdefault "lockdown,yama,bpf" if DEFAULT_SECURITY_DAC
\tdefault "lockdown,yama,selinux,bpf"
\thelp
\t  A comma-separated list of LSMs, in initialization order.

'''
KCONFIG_SUFFIX = '''config SECURITY_OTHER
\tstring "Unrelated setting"
\tdefault "lockdown,other"
\thelp
\t  Preserve this default and its help text.

source "security/baseband-guard/Kconfig"
endmenu
'''


class BasebandGuardConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(prefix=".test-bbg-", dir=REPO_ROOT)
        self.addCleanup(self.temp_dir.cleanup)
        self.work_dir = Path(self.temp_dir.name)
        self.common_dir = self.work_dir / "common"
        self.kconfig = self.common_dir / "security/Kconfig"
        self.defconfig = self.common_dir / "arch/arm64/configs/gki_defconfig"
        self.kconfig.parent.mkdir(parents=True)
        self.defconfig.parent.mkdir(parents=True)
        self.bbg_makefile = self.common_dir / "security/baseband-guard/Makefile"
        self.bbg_makefile.parent.mkdir()
        self.bbg_makefile.write_text(
            "obj-$(CONFIG_BBG) += bbg.o\n"
            "$(shell $(HOSTCC) -I$(srctree)/scripts/selinux/genheaders "
            "-o $(objtree)/genheaders $(srctree)/scripts/selinux/genheaders/genheaders.c)\n",
            encoding="utf-8",
        )
        self.kconfig.write_text(KCONFIG_PREFIX + LSM_CONFIG + KCONFIG_SUFFIX, encoding="utf-8")
        self.defconfig.write_text("CONFIG_SECURITY=y\nCONFIG_SECURITY_SELINUX=y\n", encoding="utf-8")

    def configure(self):
        KernelBuilder._configure_bbg_lsm(self.common_dir)

    def make_builder(self, enabled=True):
        builder = object.__new__(KernelBuilder)
        builder.config = SimpleNamespace(use_bbg=enabled)
        builder.work_dir = self.work_dir
        builder._chdir = Mock()
        builder._run_cmd = Mock(return_value=subprocess.CompletedProcess("setup", 0))
        return builder

    def test_add_bbg_preserves_other_security_configuration(self):
        builder = self.make_builder()
        builder.add_bbg()
        content = self.kconfig.read_text(encoding="utf-8")
        self.assertTrue(content.startswith(KCONFIG_PREFIX))
        self.assertTrue(content.endswith(KCONFIG_SUFFIX))
        self.assertIn('default "lockdown,yama,selinux,bpf,baseband_guard"', content)
        self.assertIn("CONFIG_BBG=y\n", self.defconfig.read_text(encoding="utf-8"))

    def test_all_conditional_defaults_preserve_their_values_and_conditions(self):
        self.configure()
        expected = LSM_CONFIG
        for original in (
            "lockdown,yama,smack,selinux,bpf",
            "lockdown,yama,apparmor,selinux,bpf",
            "lockdown,yama,tomoyo,bpf",
            "lockdown,yama,bpf",
            "lockdown,yama,selinux,bpf",
        ):
            expected = expected.replace('"' + original + '"', '"' + original + ',baseband_guard"')
        self.assertEqual(self.kconfig.read_text(encoding="utf-8"), KCONFIG_PREFIX + expected + KCONFIG_SUFFIX)

    def test_repeated_configuration_is_idempotent(self):
        self.configure()
        first = (self.kconfig.read_bytes(), self.defconfig.read_bytes())
        self.configure()
        self.assertEqual(first, (self.kconfig.read_bytes(), self.defconfig.read_bytes()))
        self.assertEqual(self.defconfig.read_text(encoding="utf-8").count("CONFIG_BBG=y"), 1)

    def test_default_without_lockdown_is_extended(self):
        self.kconfig.write_text('config LSM\n\tstring "LSMs"\n\tdefault "selinux,bpf"\n', encoding="utf-8")
        self.configure()
        self.assertIn('default "selinux,bpf,baseband_guard"', self.kconfig.read_text(encoding="utf-8"))

    def test_empty_defaults_and_explicit_lsm_have_no_leading_comma(self):
        self.kconfig.write_text('config LSM\n\tstring "LSMs"\n\tdefault ""\n', encoding="utf-8")
        self.defconfig.write_text('CONFIG_SECURITY=y\nCONFIG_LSM=""\n', encoding="utf-8")
        self.configure()
        self.assertIn('default "baseband_guard"', self.kconfig.read_text(encoding="utf-8"))
        self.assertIn('CONFIG_LSM="baseband_guard"', self.defconfig.read_text(encoding="utf-8"))

    def test_explicit_lsm_preserves_existing_modules(self):
        self.defconfig.write_text('CONFIG_SECURITY=y\nCONFIG_LSM="selinux,yama,bpf"\n', encoding="utf-8")
        self.configure()
        self.assertIn('CONFIG_LSM="selinux,yama,bpf,baseband_guard"\n', self.defconfig.read_text(encoding="utf-8"))

    def test_existing_guard_in_list_is_preserved_once(self):
        original = 'config LSM\n\tstring "LSMs"\n\tdefault "baseband_guard,selinux"\n'
        self.kconfig.write_text(original, encoding="utf-8")
        self.defconfig.write_text('CONFIG_BBG=y\nCONFIG_LSM="baseband_guard,selinux"\n', encoding="utf-8")
        self.configure()
        self.assertEqual(self.kconfig.read_text(encoding="utf-8"), original)
        self.assertEqual(self.defconfig.read_text(encoding="utf-8"), 'CONFIG_BBG=y\nCONFIG_LSM="baseband_guard,selinux"\n')

    def test_disabled_defconfig_guard_is_enabled_without_duplicates(self):
        for setting in ("CONFIG_BBG=n", "# CONFIG_BBG is not set", "CONFIG_BBG=y"):
            with self.subTest(setting=setting):
                self.defconfig.write_text("CONFIG_SECURITY=y\n" + setting + "\n", encoding="utf-8")
                self.configure()
                self.assertEqual(self.defconfig.read_text(encoding="utf-8"), "CONFIG_SECURITY=y\nCONFIG_BBG=y\n")

    def test_disabled_feature_keeps_files_and_commands_unchanged(self):
        initial = (self.kconfig.read_bytes(), self.defconfig.read_bytes())
        builder = self.make_builder(enabled=False)
        builder.add_bbg()
        self.assertEqual(initial, (self.kconfig.read_bytes(), self.defconfig.read_bytes()))
        builder._chdir.assert_not_called()
        builder._run_cmd.assert_not_called()

    def test_setup_commands_check_exit_status(self):
        builder = self.make_builder()
        builder.add_bbg()
        self.assertEqual(builder._run_cmd.call_count, 2)
        for call in builder._run_cmd.call_args_list:
            self.assertTrue(call.kwargs.get("check", True))

    def test_header_generator_inherits_android_host_flags(self):
        self.make_builder().add_bbg()
        content = self.bbg_makefile.read_text(encoding="utf-8")
        self.assertIn("$(HOSTCC) $(KBUILD_HOSTCFLAGS) $(KBUILD_HOSTLDFLAGS) -I", content)
        self.assertIn("obj-$(CONFIG_BBG) += bbg.o\n", content)

    def test_header_generator_update_is_idempotent(self):
        KernelBuilder._configure_bbg_host_tools(self.common_dir)
        first = self.bbg_makefile.read_bytes()
        KernelBuilder._configure_bbg_host_tools(self.common_dir)
        self.assertEqual(self.bbg_makefile.read_bytes(), first)

    def test_setup_failure_preserves_configuration_and_cleans_script(self):
        initial = (self.kconfig.read_bytes(), self.defconfig.read_bytes())
        for failure_stage in (1, 2):
            with self.subTest(failure_stage=failure_stage):
                setup_file = self.common_dir / ".bbg-setup.sh"
                setup_file.write_text("#!/bin/sh\n", encoding="utf-8")
                builder = self.make_builder()
                builder._run_cmd.side_effect = (
                    [subprocess.CompletedProcess("download", 0)] * (failure_stage - 1)
                    + [subprocess.CalledProcessError(1, "setup")]
                )
                with self.assertRaises(subprocess.CalledProcessError):
                    builder.add_bbg()
                self.assertEqual(builder._run_cmd.call_count, failure_stage)
                self.assertEqual(initial, (self.kconfig.read_bytes(), self.defconfig.read_bytes()))
                self.assertFalse(setup_file.exists())

    def test_missing_exact_lsm_section_raises(self):
        self.kconfig.write_text(KCONFIG_PREFIX + KCONFIG_SUFFIX, encoding="utf-8")
        with self.assertRaises(RuntimeError):
            self.configure()

    def test_missing_quoted_lsm_default_raises(self):
        self.kconfig.write_text(KCONFIG_PREFIX + 'config LSM\n\tstring "LSMs"\n\tdefault OTHER_LSMS\n' + KCONFIG_SUFFIX, encoding="utf-8")
        with self.assertRaises(RuntimeError):
            self.configure()

    def test_missing_required_files_raise(self):
        for path in (self.kconfig, self.defconfig):
            with self.subTest(path=path.name):
                content = path.read_bytes()
                path.unlink()
                try:
                    with self.assertRaises(OSError):
                        self.configure()
                finally:
                    path.write_bytes(content)


if __name__ == "__main__":
    unittest.main()
