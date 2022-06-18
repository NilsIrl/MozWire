use std::{num::ParseIntError, str::FromStr};

use clap::{ArgGroup, Args, Parser, Subcommand, ValueEnum};
use regex::Regex;

#[derive(Parser)]
#[clap(
    author,
    about,
    version,
    after_help = "To query MozillaVPN, mozwire requires a token, specified with --token. If it is \
                  left unspecified, mozwire will generate a token by opening a login page, the \
                  token generated can be printed using --print-token, so that it can be reused. \
                  To generate a WireGuard configuration use `mozwire relay save`.",
    arg_required_else_help = true
)]
pub struct Cli {
    #[clap(subcommand)]
    pub(crate) command: Option<Commands>,
    /// By default, mozwire will open the login page in a browser, this option prevents mozwire a browser page from being opened.
    #[clap(long, global = true)]
    pub(crate) no_browser: bool,
    /// The token used to communicate with the Mozilla API. If unspecified, a web page will be opened to retrieve the token. the MOZ_TOKEN environment variable can also be used instead.
    #[clap(long, global = true, env = "MOZ_TOKEN")]
    pub(crate) token: Option<String>,
    /// Print the token used to query the Mozilla API, so that it can be reused with --token, without having to sign in each time.
    #[clap(long, global = true)]
    pub(crate) print_token: bool,
}

#[derive(Subcommand)]
pub(crate) enum Commands {
    /// Add, remove and list devices. To connect to MozillaVPN, a device needs to be on the list.
    Device {
        #[clap(subcommand)]
        command: DeviceCommands,
    },
    Relay {
        #[clap(subcommand)]
        command: RelayCommands,
    },
}

#[derive(ValueEnum, Clone)]
pub(crate) enum Tunnel {
    Both,
    Ipv4,
    Ipv6,
}

pub(crate) enum Port {
    Random,
    Port(u16),
}

impl FromStr for Port {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "random" => Ok(Self::Random),
            port => Ok(Self::Port(port.parse()?)),
        }
    }
}

impl Default for Tunnel {
    fn default() -> Self {
        Self::Both
    }
}

#[derive(Args)]
pub(crate) struct NameArgs {
    /// Name linked with a public key. Defaults to the hostname of the system. This value has no effect on the functioning of the VPN.
    #[clap(long, default_value_t = sys_info::hostname().unwrap())]
    pub(crate) name: String,
}

/// List available relays (VPN Servers) and save WireGuard configurations for these.
#[derive(Subcommand)]
pub(crate) enum RelayCommands {
    /// List relays
    #[clap(alias = "ls")]
    List,
    /// Save wireguard configuration for a MozillaVPN server. If the private key used is not in the device list uploaded, mozwire will upload it.
    #[clap(group(ArgGroup::new("port-or-hop").args(&["hop", "port"])))]
    Save {
        /// Regex to filter servers by hostname.
        #[clap(default_value = "")]
        regex: Regex,
        /// Directory in which to output the WireGuard configuration. Defaults to the current directory
        #[clap(default_value = ".", short)]
        output: String,
        /// Private key to use in the configuration file. If it is not specified, mozwire will generate one and update the device list.
        #[clap(long)]
        privkey: Option<String>,
        /// Port to use. This can be changed to bypass firewalls and dissimulate the use of WireGuard. A value of "random" will choose a random port within the available range, which is the only available behaviour of the windows MozillaVPN client.
        #[clap(default_value = "51820", short)]
        port: Port,
        /// Select whether to tunnel both ipv4 and ipv6, only ipv4 or only ipv6.
        #[clap(long, value_enum, default_value_t)]
        tunnel: Tunnel,
        /// Limit the number of servers saved. A value of 0 disables the limit.
        #[clap(short, default_value_t = 1)]
        limit: usize,
        /// Enables a kill switch
        #[clap(long)]
        killswitch: bool,
        /// Intermediate server (entry node) to connect to for multihop with wireguard.
        #[clap(long)]
        hop: Option<String>,
        #[clap(flatten)]
        name: NameArgs,
    },
}

#[derive(Subcommand)]
pub(crate) enum DeviceCommands {
    /// Add a device to the device list, so it can be used to connect to MozillaVPN
    #[clap(group(ArgGroup::new("key").required(true).args(&["pubkey", "privkey"])))]
    Add {
        #[clap(long)]
        pubkey: Option<String>,
        #[clap(long)]
        privkey: Option<String>,
        #[clap(flatten)]
        name: NameArgs,
    },
    /// List devices
    #[clap(alias = "ls")]
    List,
    /// Remove one or multiple devices
    #[clap(alias = "rm")]
    Remove {
        /// Public, private key or name of the device(s) to remove.
        #[clap(required = true)]
        ids: Vec<String>,
    },
}
