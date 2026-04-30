# apt-cacher-rs

[![Version info](https://img.shields.io/crates/v/apt-cacher-rs.svg)](https://crates.io/crates/apt-cacher-rs)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE?raw=true)

`apt-cacher-rs` is a simple caching proxy daemon for Debian style repositories.
It is inspired by and an alternative to [`apt-cacher`](https://salsa.debian.org/LeePen/apt-cacher) and [`apt-cacher-ng`](https://www.unix-ag.uni-kl.de/~bloch/acng/).

## Build the Debian package

Before you can create a Debian package, the following commands must be run once to install the necessary dependencies:

```bash
apt-get -y install dpkg-dev liblzma-dev
cargo install cargo-deb
```

Then run the following command to build the Debian package in `target/debian/apt-cacher-rs.deb`:

```bash
cargo deb
```

## Build container image

`apt-cacher-rs` can be easily run inside a container.

Build an image with the following command based on the in-tree [Dockerfile](Dockerfile):

```bash
podman build -t apt-cacher-rs:dev -f Dockerfile .
```

The image expects a `volume` mounted at */data* to store the database and cached files.
You must also provide a configuration file via a mount on */app/apt-cacher-rs.conf*, since the default configuration does not permit any clients.
For example you can start a container via:

```bash
podman run -p 3142:3142/tcp --read-only --rm -v apt-cacher-rs-data:/data:nodev,noexec,nosuid -v /srv/apt-cacher-rs.conf:/app/apt-cacher-rs.conf:ro apt-cacher-rs:dev
```

The image's `ENTRYPOINT` hard-codes `--config-file=/app/apt-cacher-rs.conf`, `--cache-path=/data/cache` and `--database-path=/data/apt-cacher-rs.db`; any extra arguments passed to `podman run` are appended after these flags.
To use different paths, override the entrypoint via `--entrypoint`.

## Command-line options

The most relevant flags (see `apt-cacher-rs --help` for the full list):

- `--config-file=<PATH>`: path to the configuration file (default */etc/apt-cacher-rs/apt-cacher-rs.conf*).
  If the default file is missing the built-in defaults are used; a missing non-default file is an error.
- `--cache-path=<PATH>`: overrides the `cache_directory` field from the configuration file (or its default).
- `--database-path=<PATH>`: overrides the `database_path` field from the configuration file (or its default).

## How to use

Install the Debian package via dpkg on a local network server and add the following configuration file on every client system that should utilize the proxy:

*/etc/apt/apt.conf.d/30proxy*
```
Acquire::http::Proxy "http://<proxy_ip>:3142/";
```

If your sources contain HTTPS repositories you like to cache as well, change their URL schema to *http://* to cache their packages.
Note that connections from the client to the proxy are unencrypted (but all packages are by default verified by `apt(8)` after download to have a valid GPG signature).

## Web interface

`apt-cacher-rs` contains a minimal web interface for some statistics at *`http://<proxy-ip>:3142/`*, and important logs can be viewed at *`http://<proxy-ip>:3142/logs`*.

## Cleanup

Packages in the cache that are no longer referenced by any known upstream repository are pruned every 24h, unless they have been downloaded less than 3 days ago.
The list of known upstream repositories is gathered by inspecting proxied package list requests (i.e. by *apt update*).
The cleanup can also be manually triggered by sending the signal `USR2` to the `apt-cacher-rs` process.

`apt-cacher-rs` also reacts to these maintenance signals:
- `USR1`: reopen the active log file (when logging to a file)

## TLS

By default [`rustls`](https://github.com/rustls/rustls) is used as TLS backend.
To use the system provided TLS implementation disable default cargo features and enable the cargo feature `tls_hyper`.

## Security

The proxy interface should not be made public available to the internet or completely untrusted clients.
That could lead to Denial of Service issues, like congesting the network traffic or exhausting the filesystem's capacity.

## License

[MIT License](LICENSE?raw=true)
