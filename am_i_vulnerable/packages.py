import os
import re
import shutil
import subprocess
from dataclasses import dataclass


@dataclass
class Package:
    name: str
    version: str


@dataclass
class CmdResult:
    command: list
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self):
        return self.returncode == 0

    @property
    def output(self):
        return (self.stdout + "\n" + self.stderr).strip()

    @property
    def is_conflict(self):
        text = self.output.lower()
        markers = (
            "conflict",
            "unmet dependenc",
            "held broken",
            "dpkg was interrupted",
            "unable to lock",
            "error:",
            "failed",
        )
        return self.returncode != 0 or any(marker in text for marker in markers)


def run_cmd(cmd, timeout=600, extra_env=None):
    env = dict(os.environ)
    env["DEBIAN_FRONTEND"] = "noninteractive"
    env["LC_ALL"] = "C"
    if extra_env:
        env.update(extra_env)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
        return CmdResult(list(cmd), proc.returncode, proc.stdout, proc.stderr)
    except subprocess.TimeoutExpired:
        return CmdResult(list(cmd), 124, "", f"timeout after {timeout}s")
    except FileNotFoundError as exc:
        return CmdResult(list(cmd), 127, "", str(exc))


def parse_dpkg_output(text):
    packages = []
    for line in text.splitlines():
        if "\t" in line:
            name, version = line.split("\t", 1)
            name = name.strip()
            version = version.strip()
            if name:
                packages.append(Package(name, version))
    return packages


def parse_rpm_output(text):
    packages = []
    for line in text.splitlines():
        if "\t" in line:
            name, version = line.split("\t", 1)
            if name.strip():
                packages.append(Package(name.strip(), version.strip()))
    return packages


def parse_pacman_output(text):
    packages = []
    for line in text.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2:
            packages.append(Package(parts[0], parts[1].strip()))
    return packages


_APK_RE = re.compile(r"^(.+)-([0-9].*)$")


def parse_apk_output(text):
    packages = []
    for line in text.splitlines():
        line = line.strip()
        match = _APK_RE.match(line)
        if match:
            packages.append(Package(match.group(1), match.group(2)))
    return packages


def match_package(installed_map, name):
    if not name:
        return None
    normalized = name.strip().lower()
    stripped = normalized.replace("_", "").replace("-", "")
    for candidate in (normalized, normalized.replace("_", "-"), normalized.replace("-", "_"), stripped):
        if candidate in installed_map:
            return installed_map[candidate]
    return None


class PackageManager:
    name = "generic"

    def list_installed(self):
        raise NotImplementedError

    def refresh_index(self):
        return CmdResult([], 0, "", "")

    def update_available(self, package):
        return False

    def update(self, package):
        raise NotImplementedError

    def installed_map(self):
        return {pkg.name.lower(): pkg for pkg in self.list_installed()}


class AptManager(PackageManager):
    name = "apt"

    def list_installed(self):
        res = run_cmd(["dpkg-query", "-W", "-f=${Package}\\t${Version}\\n"], timeout=180)
        return parse_dpkg_output(res.stdout)

    def refresh_index(self):
        return run_cmd(["apt-get", "update"], timeout=900)

    def update_available(self, package):
        res = run_cmd(["apt-cache", "policy", package], timeout=120)
        installed = None
        candidate = None
        for line in res.stdout.splitlines():
            stripped = line.strip()
            if stripped.startswith("Installed:"):
                installed = stripped.split(":", 1)[1].strip()
            elif stripped.startswith("Candidate:"):
                candidate = stripped.split(":", 1)[1].strip()
        if not candidate or candidate == "(none)":
            return False
        return candidate != installed

    def update(self, package):
        return run_cmd(
            [
                "apt-get",
                "install",
                "-y",
                "--only-upgrade",
                "-o",
                "Dpkg::Options::=--force-confdef",
                "-o",
                "Dpkg::Options::=--force-confold",
                package,
            ],
            timeout=1800,
        )


class DnfManager(PackageManager):
    name = "dnf"

    def list_installed(self):
        res = run_cmd(["rpm", "-qa", "--qf", "%{NAME}\\t%{VERSION}-%{RELEASE}\\n"], timeout=180)
        return parse_rpm_output(res.stdout)

    def refresh_index(self):
        return run_cmd(["dnf", "makecache", "--refresh"], timeout=900)

    def update_available(self, package):
        res = run_cmd(["dnf", "check-update", package], timeout=300)
        return res.returncode == 100

    def update(self, package):
        return run_cmd(["dnf", "update", "-y", package], timeout=1800)


class PacmanManager(PackageManager):
    name = "pacman"

    def list_installed(self):
        res = run_cmd(["pacman", "-Q"], timeout=180)
        return parse_pacman_output(res.stdout)

    def refresh_index(self):
        return run_cmd(["pacman", "-Sy", "--noconfirm"], timeout=900)

    def update_available(self, package):
        return run_cmd(["pacman", "-Qu", package], timeout=120).returncode == 0

    def update(self, package):
        return run_cmd(["pacman", "-Syu", "--noconfirm", "--needed", package], timeout=1800)


class ApkManager(PackageManager):
    name = "apk"

    def list_installed(self):
        res = run_cmd(["apk", "info", "-v"], timeout=180)
        return parse_apk_output(res.stdout)

    def refresh_index(self):
        return run_cmd(["apk", "update"], timeout=900)

    def update_available(self, package):
        res = run_cmd(["apk", "upgrade", "--simulate", package], timeout=300)
        return res.ok and package in res.stdout

    def update(self, package):
        return run_cmd(["apk", "upgrade", package], timeout=1800)


class ZypperManager(PackageManager):
    name = "zypper"

    def list_installed(self):
        res = run_cmd(["rpm", "-qa", "--qf", "%{NAME}\\t%{VERSION}-%{RELEASE}\\n"], timeout=180)
        return parse_rpm_output(res.stdout)

    def refresh_index(self):
        return run_cmd(["zypper", "--non-interactive", "refresh"], timeout=900)

    def update_available(self, package):
        res = run_cmd(["zypper", "--non-interactive", "list-updates", package], timeout=300)
        if not res.ok:
            return False
        for line in res.stdout.splitlines():
            cells = [cell.strip() for cell in line.split("|")]
            if cells and cells[0] == package:
                return True
        return False

    def update(self, package):
        return run_cmd(["zypper", "--non-interactive", "update", package], timeout=1800)


_MANAGERS = (
    ("apt-get", AptManager),
    ("dnf", DnfManager),
    ("pacman", PacmanManager),
    ("apk", ApkManager),
    ("zypper", ZypperManager),
)


def detect():
    for binary, cls in _MANAGERS:
        if shutil.which(binary):
            return cls()
    raise RuntimeError("Kein unterstuetzter Paketmanager gefunden (apt, dnf, pacman, apk, zypper)")
