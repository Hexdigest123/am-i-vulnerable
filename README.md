# Am I Vulnerable

A minimal C systemd daemon scaffold. The daemon wakes up on an interval and
calls `check_for_vulnerabilities()` in [`src/main.c`](src/main.c), which is the
place to add the actual feed/package logic.

## Layout

```text
src/main.c                          daemon entry point and check hook
systemd/am-i-vulnerable.service     systemd unit
Makefile                            build, install, and package targets
VERSION                             release version
.github/workflows/build.yml         CI build and release workflow
```

## Dependencies

A C11 compiler, GNU Make, `pkg-config`, libcurl, libxml2, and systemd.

On Debian/Ubuntu install the development packages with:

```bash
sudo apt install build-essential pkg-config libcurl4-openssl-dev libxml2-dev
```

## Build and run

```bash
make                # build ./am-i-vulnerable
make check          # smoke test the binary
./am-i-vulnerable   # run in the foreground
```

The check interval defaults to 5 hours and can be overridden with
`AMI_VULNERABLE_INTERVAL_SECONDS`:

```bash
AMI_VULNERABLE_INTERVAL_SECONDS=60 ./am-i-vulnerable
```

## Install

```bash
sudo make install
sudo systemctl daemon-reload
sudo systemctl enable --now am-i-vulnerable
journalctl -u am-i-vulnerable -f
```

The default prefix is `/usr/local`, so the binary is installed to
`/usr/local/bin/am-i-vulnerable` and the unit to
`/usr/local/lib/systemd/system/am-i-vulnerable.service`. Use
`sudo make uninstall` to remove both files.

Edit the interval directly in the unit if you prefer:

```ini
Environment=AMI_VULNERABLE_INTERVAL_SECONDS=18000
```

## Build a package

```bash
make dist
```

This creates `dist/am-i-vulnerable-<version>-<commit>.tar.gz` containing an
installable `usr/local` tree. Extract it at the filesystem root:

```bash
sudo tar -C / -xzf dist/am-i-vulnerable-*.tar.gz
sudo systemctl daemon-reload
```

## Branches and CI

- `main` is built automatically on every push. The tarball is attached to the
  workflow run as a GitHub Actions artifact.
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
