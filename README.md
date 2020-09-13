# MozWire

[![Crates.io](https://img.shields.io/crates/v/mozwire)][crates.io]
[![GitHub All Releases](https://img.shields.io/github/downloads/NilsIrl/mozwire/total?label=Github%20Downloads)][release page]
[![Crates.io](https://img.shields.io/crates/d/mozwire?label=Crates.io%20Downloads)][crates.io]
![GitHub Workflow Status (branch)](https://img.shields.io/github/workflow/status/NilsIrl/mozwire/Rust/trunk)

MozWire is an unofficial cross-platform client for MozillaVPN, finally giving
Linux, macOS, FreeBSD, OpenBSD and others (all platforms supporting the
WireGuard protocol) users access to this VPN provider. MozWire also supports
Windows.

## Features

* Support for [multihop] servers (Not available on official clients)
* Select individual servers (as opposed to being limited to choosing cities) (Not available on official clients)
* Select custom remote port, bypassing firewalls (Not available on official clients)
* Support for other operating systems (Not available on official clients)
* Use "native" WireGuard clients with more customizability (Not available on official clients)
* Tunnel only IPv6 traffic (Not available on official clients)
* Supports kill switch
* Works with [socks5 multihop]

## Installation

### Using pre-built binaries from the CI (Linux, macOS and Windows) (Recommended)

Linux, macOS and Windows binaries are available on the [release page]. These
binaries are built by GitHub Actions CI.

### Using the [AUR] for [Arch Linux] users

The package name is [`mozwire`](https://aur.archlinux.org/packages/mozwire) and
can be installed using your favourite [AUR helper]:

```sh
yay -S mozwire
```

### Using Nix
`mozwire` is now packaged in
[nixpkgs](https://github.com/NixOS/nixpkgs/pull/95754), make sure your
`nixpkgs-unstable` channel is up to date (`nix-channel --update
nixpkgs-unstable`), then run

```sh
nix-env -i MozWire
```

### Using `cargo install`

#### From [crates.io]

```sh
cargo install mozwire
```

#### From git

```sh
cargo install --git https://github.com/NilsIrl/MozWire.git --branch trunk
```

### Building

```
git clone https://github.com/NilsIrl/MozWire.git
cd MozWire
cargo build
```

## Usage

`mozwire relay save` to generate a WireGuard configuration. `--help` to get help
on a subcommand, e.g. `mozwire relay --help`, `mozwire relay save --help`.

### Examples

Output configuration for all servers into the `/etc/wireguard` directory.

```sh
mozwire relay save -o /etc/wireguard -n 0
```

Use `MOZ_TOKEN` to "cache" the token instead of specifying it each time with
`--token` or log in each time.

```sh
export MOZ_TOKEN=$(mozwire --print-token) # save the token in the MOZ_TOKEN environment variable
mozwire .... # mozwire commands can be run without having to log in
```

[![asciicast](https://asciinema.org/a/wQgorg0PgkrjI52NSWEdzdQ7U.svg)](https://asciinema.org/a/wQgorg0PgkrjI52NSWEdzdQ7U)

```
mozwire 0.5.2
Nils <nils@nilsand.re>
MozillaVPN wireguard configuration manager

USAGE:
    mozwire [FLAGS] [OPTIONS] [SUBCOMMAND]

FLAGS:
    -h, --help           Prints help information
        --no-browser     By default, mozwire will open the login page in a
                         browser, this option prevents mozwire a browser page
                         from being opened.
        --print-token    Print the token used to query the Mozilla API, so that
                         it can be reused with --token, without having to sign
                         in each time.
    -V, --version        Prints version information

OPTIONS:
        --token <token>    The token used to communicate with the Mozilla API.
                           If unspecified, a web page will be opened to retrieve
                           the token. the MOZ_TOKEN environment variable can
                           also be used instead. [env: MOZ_TOKEN=]

SUBCOMMANDS:
    device    Add, remove and list devices. To connect to MozillaVPN, a
              device needs to be on the list.
    help      Prints this message or the help of the given subcommand(s)
    relay     List available relays (VPN Servers) and save WireGuard
              configurations for these.

To query MozillaVPN, mozwire requires a token, specified with --token. If it is
left unspecified, mozwire will generate a token by opening a login page, the
token generated can be printed using --print-token, so that it can be reused. To
generate a WireGuard configuration use `mozwire relay save`.
```

## Contact

[mozwire@nilsand.re](mailto:mozwire@nilsand.re)

## License and Copyright

MozWire is licensed under the GNU GENERAL PUBLIC LICENSE Version 3. I am willing
to relicense it.

Copyright © 2020 Nils André

[Arch Linux]: https://www.archlinux.org/
[AUR]: https://wiki.archlinux.org/index.php/Arch_User_Repository
[AUR Helper]: https://wiki.archlinux.org/index.php/AUR_helpers
[crates.io]: https://crates.io/crates/mozwire
[multihop]: https://mullvad.net/en/help/multihop-wireguard/
[release page]: https://github.com/NilsIrl/MozWire/releases
[socks5 multihop]: https://mullvad.net/en/help/different-entryexit-node-using-wireguard-and-socks5-proxy/
