# MozWire

MozWire is a cross-platform client for MozillaVPN, finally giving Linux, macOS,
FreeBSD, OpenBSD and others (all platform supporting the WireGuard protocol)
users access to this VPN provider. MozWire also supports Windows.

## Installation

### Using pre-built binaries from the CI (Linux, macOS and Windows) (Recommended)

Linux, macOS and Windows binaries are available on the [release page]. These
binaries have built by GitHub actions CI.

### Using `cargo install`

From crates.io:

```sh
cargo install mozwire
```

From git:

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

[![asciicast](https://asciinema.org/a/002XVrcKQYcWOwP15OLVLjEL9.svg)](https://asciinema.org/a/002XVrcKQYcWOwP15OLVLjEL9)

```
mozwire 0.2.0
Nils <nils@nilsand.re>
MozillaVPN wireguard configuration manager

USAGE:
    mozwire [FLAGS] [OPTIONS] [SUBCOMMAND]

FLAGS:
    -h, --help           Prints help information
        --no-browser     By default, mozwire will open the login page in a browser, this option prevents
                         mozwire a browser page from being opened.
        --print-token    Print the token used to query the Mozilla API, so that it can be reused with
                         --token, without having to sign in each time.
    -V, --version        Prints version information

OPTIONS:
        --token <token>    The token used to communicate with the Mozilla API.
                           If unspecified, a web page will be opened to retrieve the token.

SUBCOMMANDS:
    device    Add, remove and list devices. To connect to MozillaVPN, a device needs to be in the list.
    help      Prints this message or the help of the given subcommand(s)
    relay     List available relays (VPN Servers) and save WireGuard configurations for these.

To query MozillaVPN, mozwire requires a token, specified with --token. If it is
left unspecified, mozwire will generate a token by opening a login page, the
token generated can be printed using --print-token, so that it can be reused.
To generate a WireGuard configuration use `mozwire relay save`.
```

## Contact

[mozwire@nilsand.re](mailto:mozwire@nilsand.re)

## License and Copyright

MozWire is licensed under the GNU GENERAL PUBLIC LICENSE Version 3. I am willing
to relicense it.

Copyright © Nils André

[release page]: https://github.com/NilsIrl/MozWire/releases
