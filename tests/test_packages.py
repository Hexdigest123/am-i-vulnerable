import unittest
from unittest import mock

from cvewatch import packages
from cvewatch.packages import (
    AptManager,
    CmdResult,
    Package,
    parse_apk_output,
    parse_dpkg_output,
    parse_pacman_output,
    parse_rpm_output,
)


class ParseTest(unittest.TestCase):
    def test_dpkg(self):
        out = "openssl\t3.0.13-1ubuntu1\nlibssl3\t3.0.13-1ubuntu1\nnginx\t1.24.0-1\n"
        pkgs = parse_dpkg_output(out)
        self.assertEqual([(p.name, p.version) for p in pkgs][0], ("openssl", "3.0.13-1ubuntu1"))
        self.assertEqual(len(pkgs), 3)

    def test_rpm(self):
        out = "openssl\t3.0.13-5.el9\nbash\t5.1.8-6.el9\n"
        pkgs = parse_rpm_output(out)
        self.assertEqual(pkgs[0].name, "openssl")
        self.assertEqual(pkgs[0].version, "3.0.13-5.el9")

    def test_pacman(self):
        out = "openssl 3.3.0-1\nlinux 6.8.1.arch1-1\n"
        pkgs = parse_pacman_output(out)
        self.assertEqual([(p.name, p.version) for p in pkgs], [("openssl", "3.3.0-1"), ("linux", "6.8.1.arch1-1")])

    def test_apk(self):
        out = "openssl-3.3.0-r0\nmusl-1.2.4_git20230717-r0\n"
        pkgs = parse_apk_output(out)
        self.assertEqual([(p.name, p.version) for p in pkgs], [("openssl", "3.3.0-r0"), ("musl", "1.2.4_git20230717-r0")])


class MatchTest(unittest.TestCase):
    def test_match_variants(self):
        installed = {"openssl": Package("openssl", "3.0.13"), "libssl3": Package("libssl3", "3.0.13")}
        self.assertEqual(packages.match_package(installed, "OpenSSL").name, "openssl")
        self.assertEqual(packages.match_package(installed, "libssl_3").name, "libssl3")
        self.assertIsNone(packages.match_package(installed, "notinstalled"))
        self.assertIsNone(packages.match_package(installed, ""))


class CmdResultTest(unittest.TestCase):
    def test_conflict_markers(self):
        self.assertTrue(CmdResult(["x"], 100, "", "E: Unable to lock /var/lib/dpkg/lock").is_conflict)
        self.assertTrue(CmdResult(["x"], 0, "The following packages have unmet dependencies:", "").is_conflict)
        self.assertTrue(CmdResult(["x"], 0, "dpkg: error: conflict", "").is_conflict)
        self.assertFalse(CmdResult(["x"], 0, "Setting up openssl (3.0.15) ...", "").is_conflict)


class AptManagerTest(unittest.TestCase):
    def test_update_available_parsing(self):
        policy = (
            "openssl:\n"
            "  Installed: 3.0.13-1ubuntu1\n"
            "  Candidate: 3.0.15-1ubuntu1\n"
            "  Version table:\n"
            " *** 3.0.13-1ubuntu1 500\n"
        )
        with mock.patch.object(packages, "run_cmd", return_value=CmdResult([], 0, policy, "")):
            self.assertTrue(AptManager().update_available("openssl"))
        policy_same = policy.replace("Candidate: 3.0.15-1ubuntu1", "Candidate: 3.0.13-1ubuntu1")
        with mock.patch.object(packages, "run_cmd", return_value=CmdResult([], 0, policy_same, "")):
            self.assertFalse(AptManager().update_available("openssl"))
        policy_none = "openssl:\n  Installed: (none)\n  Candidate: (none)\n"
        with mock.patch.object(packages, "run_cmd", return_value=CmdResult([], 0, policy_none, "")):
            self.assertFalse(AptManager().update_available("openssl"))

    def test_update_command(self):
        with mock.patch.object(packages, "run_cmd", return_value=CmdResult([], 0, "ok", "")) as m:
            AptManager().update("openssl")
        cmd = m.call_args[0][0]
        self.assertIn("apt-get", cmd[0])
        self.assertIn("--only-upgrade", cmd)
        self.assertEqual(cmd[-1], "openssl")


class DetectTest(unittest.TestCase):
    def test_detect_dnf(self):
        with mock.patch.object(packages.shutil, "which", side_effect=lambda b: "/usr/bin/dnf" if b == "dnf" else None):
            pm = packages.detect()
        self.assertEqual(pm.name, "dnf")

    def test_detect_none(self):
        with mock.patch.object(packages.shutil, "which", return_value=None):
            with self.assertRaises(RuntimeError):
                packages.detect()


if __name__ == "__main__":
    unittest.main()
