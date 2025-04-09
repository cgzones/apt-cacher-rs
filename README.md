# apt-cacher-rs

[![Version info](https://img.shields.io/crates/v/apt-cacher-rs.svg)](https://crates.io/crates/apt-cacher-rs)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE?raw=true)

`apt-cacher-rs` is a simple caching proxy daemon for Debian style repositories.
It is inspired by and an alternative to [`apt-cacher`](https://salsa.debian.org/LeePen/apt-cacher) and [`apt-cacher-ng`](https://www.unix-ag.uni-kl.de/~bloch/acng/).

## Build the Debian package

Before you can compile apt-cacher-rs or create a Debian package, the following commands must be run once:

```
apt-get -y install dpkg-dev liblzma-dev
cargo install cargo-deb
```

Then run the following command to build the Debian package in `target/debian/apt-cacher-rs.deb`:

```
cargo deb
```

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
The cleanup can also be manually triggered by sending the signal `USR1` to the `apt-cacher-rs` process.

## TLS

By default [`rustls`](https://github.com/rustls/rustls) is used as TLS backend.
To use the system provided TLS implementation disable default cargo features and enable the cargo feature `tls_hyper`.

## Security

The proxy interface should not be made public available to the internet or completely untrusted clients.
That could lead to Denial of Service issues, like congesting the network traffic or exhausting the filesystem's capacity.

## License

[MIT License](LICENSE?raw=true)
