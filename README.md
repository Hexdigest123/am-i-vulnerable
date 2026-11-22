# Am I Vulnerable

A small C systemd daemon that watches an RSS CVE feed and upgrades installed
packages when the feed reports a fix. On each interval it fetches the
configured feed, reads the package entries, compares them with the packages
installed on the host, and runs the host package manager (`apt`, `dnf`, or
`pacman`) when an entry applies.

The installed package list is read once at startup and reused for the lifetime
of the daemon; the feed is fetched on every interval.

## Layout

```text
src/main.c                          daemon loop and update orchestration
src/config.c, src/config.h          config parsing and platform detection
src/rss.c, src/rss.h                feed download and RSS parsing
src/system.c, src/system.h          package listing and updates
src/version.c, src/version.h        dpkg-style version comparison
systemd/am-i-vulnerable.service     systemd unit
Makefile                            build, install, and package targets
VERSION                             release version
.github/workflows/build.yml         CI build and release workflow
```

## Dependencies

Build: a C11 compiler, GNU Make, `pkg-config`, libcurl, and libxml2.
Runtime: systemd for the service unit.

On Debian/Ubuntu install the development packages with:

```bash
sudo apt install build-essential pkg-config libcurl4-openssl-dev libxml2-dev
```

## Configuration

Release builds read `/etc/am-i-vulnerable.conf`; development builds (`make dev`)
read `am-i-vulnerable.conf` from the current directory. The file contains
`key=value` lines; empty lines and lines starting with `#` are ignored.

```ini
# Required: the feed URL.
url=https://example.com/cve/feed.xml

# Seconds between checks. Default: 18000 (5 hours).
interval=18000

# Optional. Normally detected from /etc/os-release.
# 0=Ubuntu, 1=Debian, 2=Fedora, 3=Arch; 4 or omitted means auto-detect.
platform=4
```

| Key | Meaning |
| --- | --- |
| `name` | Instance name (default: `am-i-vulnerable`). Currently informational. |
| `url` | Feed URL. Required and must not be empty. Release builds require an `https://` prefix. |
| `interval` | Seconds between checks. Default: `18000` (5 hours). |
| `platform` | Optional numeric override; auto-detected from `/etc/os-release` when omitted or set to `4`. |

`AMI_VULNERABLE_INTERVAL_SECONDS` overrides `interval` when it contains a
positive integer.

If the config file is missing, the daemon attempts to create a default one
with mode `0640` and then exits because `url` is empty. Create the file before
starting the service:

```bash
sudo tee /etc/am-i-vulnerable.conf >/dev/null <<'EOF'
url=https://example.com/cve/feed.xml
interval=18000
EOF
sudo chmod 0640 /etc/am-i-vulnerable.conf
```

The daemon exits at startup if the configured URL is invalid, the platform
cannot be detected, or the installed package list cannot be read.

## Build and run

```bash
make                # build the release binary ./am-i-vulnerable
make check          # smoke test: ./am-i-vulnerable --help
```

Development builds skip the root check and accept `http://` URLs. Create a
local config and run `make dev`:

```bash
cat > am-i-vulnerable.conf <<'EOF'
url=https://example.com/cve/feed.xml
interval=60
EOF
make dev
```

A release build must run as root and reads `/etc/am-i-vulnerable.conf`:

```bash
sudo ./am-i-vulnerable
```

The default interval is 5 hours. Override it in the config file or with the
environment variable; the environment variable takes precedence:

```bash
AMI_VULNERABLE_INTERVAL_SECONDS=60 make dev
```

## Security notes

- Release builds refuse to run unless the effective UID is 0 (the package
  managers need it). Development builds skip this check.
- The configured feed URL must be non-empty and free of ASCII control
  characters and spaces; release builds additionally require an `https://`
  prefix. Redirects are followed up to five times.
- The feed is parsed with `xmlReadMemory(..., XML_PARSE_NONET)`. Entity
  substitution, external DTD loading, and recovery are not enabled.
- Package updates use `fork()` and `execvp()` (never a shell), and package
  names are validated against a conservative charset before use.
- An update is only attempted when the feed entry's `ecosystem` is empty or
  matches the host platform, **and** the installed version compares older than
  the feed's `fixed` version (dpkg-style comparison, exact package-name match).
- Successful `name=fixed` updates are skipped for the lifetime of the daemon
  process; failed updates are retried on each interval. Updates and failures
  are logged to stderr, which systemd records in the journal.
- The systemd unit runs the daemon as root but with a hardened sandbox
  (`NoNewPrivileges`, `ProtectSystem=strict`, capability bounding, syscall
  filtering, ...). `systemd-analyze security --offline=yes` currently reports
  `2.9 OK` for the unit.
- The config file is opened with `O_NOFOLLOW` and must be a regular file; it is
  created with mode `0640`.
- The binary is built with `-fstack-protector-strong -D_FORTIFY_SOURCE=3
  -fPIE -pie -Wl,-z,relro,-z,now`; these flags are appended separately from
  `CFLAGS`/`LDFLAGS` so setting those variables does not replace them.

## Install

```bash
sudo make install
sudo tee /etc/am-i-vulnerable.conf >/dev/null <<'EOF'
url=https://example.com/cve/feed.xml
interval=18000
EOF
sudo chmod 0640 /etc/am-i-vulnerable.conf
sudo systemctl daemon-reload
sudo systemctl enable --now am-i-vulnerable
journalctl -u am-i-vulnerable -f
```

`make install` installs the binary and the unit, but not a config file. The
default prefix is `/usr/local`, so the binary is installed to
`/usr/local/bin/am-i-vulnerable` and the unit to
`/usr/local/lib/systemd/system/am-i-vulnerable.service`. Use
`sudo make uninstall` to remove both files; the config is left in place.

To change the interval for the service, edit `interval=` in the config or add
a systemd drop-in:

```bash
sudo systemctl edit am-i-vulnerable
```

```ini
[Service]
Environment=AMI_VULNERABLE_INTERVAL_SECONDS=18000
```

## Build a package

```bash
make dist
```

This creates `dist/am-i-vulnerable-<version>-<commit>.tar.gz` containing an
installable `usr/local` tree. It includes the binary and the unit, but not the
config file. Extract it at the filesystem root and create the config:

```bash
sudo tar -C / -xzf dist/am-i-vulnerable-*.tar.gz
sudo tee /etc/am-i-vulnerable.conf >/dev/null <<'EOF'
url=https://example.com/cve/feed.xml
interval=18000
EOF
sudo chmod 0640 /etc/am-i-vulnerable.conf
sudo systemctl daemon-reload
```

## Branches and CI

- Pushes to `main`, `v*` tags, and manual workflow dispatches run the workflow.
- Pushes to `main` build, test, and package the tree; the tarball is attached
  to the workflow run as a GitHub Actions artifact.
- `staging` has no automatic build. It exists for integration work; protection
  rules can be added separately.
- Pushing a `v*` tag builds the package and creates or updates a GitHub Release
  with the tarball attached.

Create a release from `main`:

```bash
git tag -a v0.1.0 -m "v0.1.0"
git push origin main v0.1.0
```

Update `VERSION` before tagging; the Makefile uses it for the binary and
package name.

## License

MIT; see [`LICENSE`](LICENSE).
