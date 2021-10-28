# truststore

trustore is a fork of [mkcert](https://github.com/FiloSottile/mkcert) which
provides a very lightweight library API for making locally-trusted development
certificates. It requires no configuration.

See [lib.go](./lib.go) for details of the public API methods provided.

## Supported root stores

truststore supports the following root stores:

* macOS system store
* Windows system store
* Linux variants that provide either
  * `update-ca-trust` (Fedora, RHEL, CentOS) or
  * `update-ca-certificates` (Ubuntu, Debian, OpenSUSE, SLES) or
  * `trust` (Arch)
* Firefox (macOS and Linux only)
* Chrome and Chromium
* Java (when `JAVA_HOME` is set)

For more information and detailed documentation on the internals, see the
[mkcert](https://github.com/FiloSottile/mkcert) documentation.

## License

Library API made available under the terms of the [MIT](./LICENSE) license.

Based on [mkcert](https://github.com/FiloSottile/mkcert), (c) mkcert authors (BSD-3-Clause)
