use core::num::NonZeroUsize;

mod cli;
mod constants;
mod device;
mod relay;

use crate::cli::{Cli, Commands, DeviceCommands, Port, RelayCommands, Tunnel};

use constants::{BASE_URL, IPV4_GATEWAY, PORT_RANGES, V1_API, V2_API};

use rand::seq::IteratorRandom;

use device::Device;
use relay::RelayList;

use clap::Parser;

#[derive(serde::Deserialize)]
struct User {
    devices: Vec<Device>,
}

#[derive(serde::Deserialize)]
struct Login {
    user: User,
    token: String,
}

#[derive(serde::Deserialize)]
struct Error {
    errno: u32,
    error: String,
}

impl Error {
    fn fail(self) -> ! {
        match self.errno {
            120 => {
                // the message, can be:
                // - Format is Authorization: Bearer [token]
                // - jwt malformed
                // - invalid token
                eprintln!("Invalid token ({})", self.error);
            }
            122 => {
                // TODO: see https://github.com/NilsIrl/MozWire/issues/2
                eprintln!("Token expired, regenerate a token by not specifying the --token option");
            }
            _ => {
                eprintln!("{}", self.error);
            }
        }
        std::process::exit(3);
    }
}

#[derive(serde::Serialize)]
struct NewDevice<'a> {
    name: &'a str,
    pubkey: &'a str,
}

fn private_to_public_key(privkey_base64: &str) -> Result<String, base64::DecodeError> {
    let mut privkey = [0; 32];
    base64::decode_config_slice(privkey_base64, base64::STANDARD, &mut privkey)?;
    Ok(base64::encode(
        x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(privkey)).as_bytes(),
    ))
}

impl NewDevice<'_> {
    fn upload(self, client: &reqwest::blocking::Client, token: &str) -> Device {
        let response = client
            .post(&format!("{}{}/vpn/device", BASE_URL, V1_API))
            .bearer_auth(token)
            .json(&self)
            .send()
            .unwrap();
        if response.status().is_success() {
            return response.json().unwrap();
        }
        response.json::<Error>().unwrap().fail();
    }
}

#[derive(serde::Serialize)]
struct AccessTokenRequest<'a> {
    code: &'a str,
    code_verifier: &'a str,
}

fn main() {
    let matches = Cli::parse();

    if matches.command.is_none() && !matches.print_token {
        use clap::CommandFactory;
        Cli::command().print_help().unwrap();
        std::process::exit(2);
    }

    let client = reqwest::blocking::Client::builder()
        // Some operations fail when no User-Agent is present
        .user_agent("Why does the api need a user agent???")
        .build()
        .unwrap();

    let login = matches.token.as_ref().map_or_else(
        || {
            // no token given
            use rand::RngCore;
            use sha2::Digest;
            let mut code_verifier_random = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut code_verifier_random);
            let mut code_verifier = [0u8; 43];
            base64::encode_config_slice(
                code_verifier_random,
                base64::URL_SAFE_NO_PAD,
                &mut code_verifier,
            );
            let mut code_challenge = String::with_capacity(43);
            base64::encode_config_buf(
                sha2::Sha256::digest(&code_verifier),
                base64::URL_SAFE_NO_PAD,
                &mut code_challenge,
            );

            use tiny_http::{Method, Server};

            let server = Server::http("127.0.0.1:0").unwrap();

            let login_url = format!(
                "{}{}/vpn/login/linux?code_challenge_method=S256&code_challenge={}&port={}",
                BASE_URL,
                V2_API,
                code_challenge,
                server.server_addr().port()
            );

            eprint!("Please visit {}.", login_url);
            if !matches.no_browser {
                match webbrowser::open(&login_url) {
                    Ok(_) => eprint!(" Link opened in browser."),
                    Err(_) => eprint!(" Failed to open link in browser, please visit it manually."),
                }
            }
            eprintln!();

            let code;
            let code_url_regex = regex::Regex::new(r"\A/\?code=([0-9a-f]{80})\z").unwrap();
            for request in server.incoming_requests() {
                if *request.method() == Method::Get {
                    match code_url_regex.captures(request.url()) {
                        Some(caps) => {
                            code = caps.get(1).unwrap();
                            return client
                                .post(&format!("{}{}/vpn/login/verify", BASE_URL, V2_API))
                                .json(&AccessTokenRequest {
                                    code: code.as_str(),
                                    code_verifier: std::str::from_utf8(&code_verifier).unwrap(),
                                })
                                .send()
                                .unwrap()
                                .json()
                                .unwrap();
                        }
                        None => (),
                    }
                }
            }
            unreachable!("Server closed without receiving code")
        },
        |token| {
            let response = client
                .get(&format!("{}{}/vpn/account", BASE_URL, V1_API))
                .bearer_auth(token.trim())
                .send()
                .unwrap();
            if !response.status().is_success() {
                response.json::<Error>().unwrap().fail();
            }

            Login {
                user: response.json::<User>().unwrap(),
                token: token.to_owned(),
            }
        },
    );

    if matches.print_token {
        println!("{}", login.token);
    }

    let mut rng = rand::thread_rng();

    match matches.command {
        Some(Commands::Device { command: device_m }) => match device_m {
            DeviceCommands::Add {
                pubkey,
                privkey,
                name,
            } => {
                let pubkey =
                    pubkey.unwrap_or_else(|| match private_to_public_key(&privkey.unwrap()) {
                        Ok(pubkey) => pubkey,
                        Err(_) => {
                            println!("Invalid private key.");
                            std::process::exit(2)
                        }
                    });
                println!(
                    "{}",
                    &NewDevice {
                        name: &name.name,
                        pubkey: &pubkey,
                    }
                    .upload(&client, &login.token),
                );
            }
            DeviceCommands::List => {
                eprintln!("Devices:");
                for device in login.user.devices {
                    println!("{}", device)
                }
            }
            DeviceCommands::Remove { ids } => {
                for id in ids {
                    for device in login.user.devices.iter().filter(|device| {
                        id == device.name
                            || id == device.pubkey
                            || private_to_public_key(&id)
                                .map_or(false, |pubkey| device.pubkey == pubkey)
                    }) {
                        client
                            .delete(&format!(
                                "{}{}/vpn/device/{}",
                                BASE_URL,
                                V1_API,
                                percent_encoding::utf8_percent_encode(
                                    &base64::encode(device.pubkey.as_bytes()),
                                    percent_encoding::NON_ALPHANUMERIC
                                )
                            ))
                            .bearer_auth(&login.token)
                            .send()
                            .unwrap();
                        eprintln!(
                            "Device {}, with public key: {} has successfully been removed.",
                            device.name, device.pubkey
                        );
                    }
                }
            }
        },
        Some(Commands::Relay { command: relay_m }) => match relay_m {
            RelayCommands::List => {
                print!("{}", RelayList::new(client));
            }
            RelayCommands::Save {
                regex,
                killswitch,
                output,
                name,
                limit,
                privkey,
                tunnel,
                hop,
                port,
                ..
            } => {
                let (pubkey_base64, privkey_base64) = privkey.map_or_else(
                    || {
                        let privkey = x25519_dalek::StaticSecret::new(&mut rand::rngs::OsRng);
                        let privkey_base64 = base64::encode(privkey.to_bytes());
                        (
                            base64::encode(x25519_dalek::PublicKey::from(&privkey).as_bytes()),
                            privkey_base64,
                        )
                    },
                    |privkey_base64| {
                        (
                            match private_to_public_key(&privkey_base64) {
                                Ok(pubkey) => pubkey,
                                Err(_) => {
                                    println!("Invalid private key.");
                                    std::process::exit(2)
                                }
                            },
                            privkey_base64.to_owned(),
                        )
                    },
                );

                let (address, allowed_ips) = {
                    let (ipv4_address, ipv6_address) = login
                        .user
                        .devices
                        .iter()
                        .find(|device| device.pubkey == pubkey_base64)
                        .map_or_else(
                            || {
                                eprintln!("Public key not in device list, uploading it.");
                                let device = NewDevice {
                                    name: &name.name,
                                    pubkey: &pubkey_base64,
                                }
                                .upload(&client, &login.token);
                                (device.ipv4_address, device.ipv6_address)
                            },
                            |device| (device.ipv4_address.clone(), device.ipv6_address.clone()),
                        );

                    match tunnel {
                        Tunnel::Both => (
                            format!("{},{}", &ipv4_address.0, &ipv6_address.0),
                            "0.0.0.0/0,::0/0",
                        ),
                        Tunnel::Ipv4 => (ipv4_address.0, "0.0.0.0/0"),
                        Tunnel::Ipv6 => (ipv6_address.0, "::0/0"),
                    }
                };

                let server_list = RelayList::new(client);
                let filtered = server_list
                    .servers()
                    .filter(|server| regex.is_match(&server.hostname));
                for server in if let Some(limit) = NonZeroUsize::new(limit) {
                    filtered.choose_multiple(&mut rng, limit.get())
                } else {
                    filtered.collect()
                } {
                    let (ip, port) = {
                        match hop {
                            Some(ref hop) => (
                                server_list
                                    .servers()
                                    .find(|server| server.hostname == *hop)
                                    .unwrap()
                                    .ipv4_addr_in,
                                server.multihop_port,
                            ),
                            None => {
                                // Deal with ranges
                                (server.ipv4_addr_in, {
                                    let mut ports =
                                        PORT_RANGES.iter().map(|(from, to)| (*from)..=(*to));
                                    match port {
                                        Port::Random => ports.flatten().choose(&mut rng).unwrap(),
                                        Port::Port(port_number) => {
                                            if ports.any(|range| range.contains(&port_number)) {
                                                port_number
                                            } else {
                                                println!(
                                                    "{} is outside of the usable port range.",
                                                    port_number
                                                );
                                                std::process::exit(2);
                                            }
                                        }
                                    }
                                })
                            }
                        }
                    };
                    // FIXME: we can use a pathbuf instead of this removes one allocation
                    let path = std::path::Path::new(&output);
                    std::fs::create_dir_all(&path).unwrap();
                    let path = path.join(format!("{}.conf", server.hostname));
                    std::fs::write(
                        &path,
                        format!(
                            "[Interface]
PrivateKey = {}
Address = {}
DNS = {}{}

[Peer]
PublicKey = {}
AllowedIPs = {}
Endpoint = {}:{}\n",
                            privkey_base64,
                            address,
                            IPV4_GATEWAY,
                            if killswitch {
                                "\nPostUp = iptables -I OUTPUT ! -o %i -m mark ! --mark $(wg show \
                                 %i fwmark) -m addrtype ! --dst-type LOCAL -j REJECT && ip6tables \
                                 -I OUTPUT ! -o %i -m mark ! --mark $(wg show %i fwmark) -m \
                                 addrtype ! --dst-type LOCAL -j REJECT
PreDown = iptables -D OUTPUT ! -o %i -m mark ! --mark $(wg show %i fwmark) -m addrtype ! \
                                 --dst-type LOCAL -j REJECT && ip6tables -D OUTPUT ! -o %i -m mark \
                                 ! --mark $(wg show %i fwmark) -m addrtype ! --dst-type LOCAL -j \
                                 REJECT"
                            } else {
                                ""
                            },
                            server.public_key,
                            allowed_ips,
                            ip,
                            port
                        ),
                    )
                    .unwrap();
                    println!("Wrote configuration to {}.", path.to_str().unwrap());
                }
            }
        },
        None => (),
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_private_to_public_key() {
        assert_eq!(
            private_to_public_key("OO9fkBohqv0mnmogkonAXBAvurjfy/DYXcpI1Yt7pEo=").unwrap(),
            "JyMv6TlARDnBfQmXFzlywOLveNV3mBMaWosFjTcYE0g="
        );
        assert_eq!(
            private_to_public_key("wD4tAq9edXWCILzf8uO7qgsOs/2gTUTvcGMhUdwS6E8=").unwrap(),
            "wv6lbcAK1L+IYJk8SgpRLgFED7/pggu8uvi8Li7OjH4="
        );

        assert_eq!(
            private_to_public_key("4AaD2YkoQ+c2ccL/fnjTmTeRdiZVhvXhiL4gApeePG4=").unwrap(),
            "idTXEeR5rjxYMgQpwbLP+2qYEYR5KinvDqfZpFg7HTo="
        );

        assert_eq!(
            private_to_public_key("iBr/jbjbij/w3BpvTvkB6r1zQvMpIx5mc1C/qnuzpnU=").unwrap(),
            "gxi5un691rLWUD4HSXM0gU4OpHt4r+yVlQ/jfDYJIR8="
        );

        assert_eq!(
            private_to_public_key("kCJuJAX+EWZ23tPK1b+Szl+m89TYxLh9ilIn+gDzZnc=").unwrap(),
            "nT4fmyCGntbuIetTOndAAF/b02p5GGj3MkOSb1wF1zY="
        );
    }
}
