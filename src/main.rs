use clap::{AppSettings, Arg, SubCommand};
// TODO remove unused `use` with clap v3
use clap::{crate_authors, crate_description, crate_name, crate_version};
use core::num::NonZeroUsize;
use rand::seq::IteratorRandom;
use std::{
    io::Write,
    net::{Ipv4Addr, Ipv6Addr},
};
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(serde::Deserialize)]
struct LoginURLs {
    login_url: String,
    verification_url: String,
    poll_interval: u64,
}

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

#[derive(serde::Deserialize)]
struct Device {
    name: String,
    pubkey: String,
    ipv4_address: String,
    ipv6_address: String,
}

fn private_to_public_key(privkey_base64: &str) -> Result<String, base64::DecodeError> {
    let mut privkey = [0; 32];
    base64::decode_config_slice(privkey_base64, base64::STANDARD, &mut privkey)?;
    Ok(base64::encode(
        PublicKey::from(&StaticSecret::from(privkey)).as_bytes(),
    ))
}

impl NewDevice<'_> {
    fn upload(self, client: &reqwest::blocking::Client, token: &str) -> Device {
        let response = client
            .post(&format!("{}/vpn/device", BASE_URL))
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

// weight, include_in_country, port_ranges omitted
// port_ranges is the same for each server
#[derive(serde::Deserialize, Debug)]
struct Server {
    hostname: String,
    ipv4_addr_in: Ipv4Addr,
    ipv6_addr_in: Ipv6Addr,
    ipv4_gateway: Ipv4Addr,
    ipv6_gateway: Ipv6Addr,
    public_key: String,
    port_ranges: Vec<(u16, u16)>,
}

// latitude and longitude omitted
#[derive(serde::Deserialize)]
struct City {
    name: String,
    code: String,
    servers: Vec<Server>,
    latitude: f64,
    longitude: f64,
}

#[derive(serde::Deserialize)]
struct Country {
    name: String,
    code: String,
    cities: Vec<City>,
}

#[derive(serde::Deserialize)]
struct ServerList {
    countries: Vec<Country>,
}

impl ServerList {
    fn new(client: reqwest::blocking::Client, token: &str) -> Self {
        client
            .get(&format!("{}/vpn/servers", BASE_URL))
            .bearer_auth(token)
            .send()
            .unwrap()
            .json::<ServerList>()
            .unwrap()
    }
}

const BASE_URL: &str = "https://vpn.mozilla.org/api/v1";
//const NAME_ARG: Arg = Arg::with_name("name");
//const PRIVKEY_ARG: Arg = Arg::with_name("privkey").long("privkey").takes_value(true);

fn app() -> clap::App<'static, 'static> {
    let name_arg = Arg::with_name("name")
        .help("Defaults to the hostname of the system. This value doesn't matter.")
        .long("name");
    clap::app_from_crate!()
        .subcommand(
            SubCommand::with_name("device")
                .about("Manage devices")
                .subcommand(
                    SubCommand::with_name("add")
                        .about("List Devices")
                        .arg(
                            Arg::with_name("pubkey")
                                .long("pubkey")
                                .takes_value(true)
                                .conflicts_with("privkey")
                                .required(true),
                        )
                        .arg(Arg::with_name("privkey").long("privkey").takes_value(true).required_unless("pubkey"))
                        .arg(&name_arg),
                )
                .subcommand(
                    SubCommand::with_name("list")
                        .alias("ls")
                        .about("List devices"),
                )
                .subcommand(
                    SubCommand::with_name("remove")
                        .alias("rm")
                        .about("Remove a device")
                        .arg(Arg::with_name("ids").help("Key or name to remove from the device list. The key can either be a public or private key.").required(true).takes_value(true).multiple(true))
                )
                .setting(AppSettings::SubcommandRequiredElseHelp),
        )
        .subcommand(
            SubCommand::with_name("relay")
                .about("Manage relays")
                .subcommand(
                    SubCommand::with_name("list")
                        .alias("ls")
                        .about("List relays"),
                )
                .subcommand(
                    SubCommand::with_name("save")
                        .about("Save wireguard configuration for a MozillaVPN server")
                        .arg(
                            Arg::with_name("regex")
                                .help("Regex to filter servers by hostname.")
                                .default_value(""),
                        )
                        .arg(Arg::with_name("output").short("o").help(
                            "Path to the output directory, output file or '-' to output to stdout. Defaults to the current directory",
                        ).default_value("."))
                        .arg(
                            Arg::with_name("privkey").long("privkey")
                                .help("Private key to use in the configuration file.").takes_value(true),
                        ).arg(&name_arg).arg(
                        Arg::with_name("port").long("port").short("p").default_value("51820")
                        .help("Port to use. This can be changed to bypass firewalls, by for example, setting it to the value of 53. A value of \"random\" will choose a random port within the available range, which is the default behaviour of the windows MozillaVPN client."))
                        .arg(
                            Arg::with_name("limit")
                                .help("Limit the number of servers saved. A value of 0 disables the limit.")
                                .short("n")
                                .default_value("1"),
                        )
                )
                .setting(AppSettings::SubcommandRequiredElseHelp),
        )
        .arg(
            Arg::with_name("print-token")
                .long("print-token")
                .help("Print the token used to query the Mozilla API.")
                .global(true)
        )
        .arg(
            Arg::with_name("token")
                .long("token")
                .help(
                    "The token used to communicate with the Mozilla API.
If unspecified, a web page will be opened to retrieve the token.",
                )
                .takes_value(true)
                .global(true),
        )
        .global_setting(AppSettings::ColoredHelp)
        .setting(AppSettings::ArgRequiredElseHelp)
}

fn main() {
    let matches = app().get_matches();

    let client = reqwest::blocking::Client::builder()
        // Some operations fail when no User-Agent is present
        .user_agent("Why does the api need a user agent???")
        .build()
        .unwrap();

    let login = matches.value_of("token").map_or_else(
        || {
            let login = client
                .post(&format!("{}/vpn/login", BASE_URL))
                .send()
                .unwrap()
                .json::<LoginURLs>()
                .unwrap();

            eprintln!("Please visit {}", login.login_url);
            match webbrowser::open(&login.login_url) {
                Ok(_) => eprintln!("Link opened in browser."),
                Err(_) => eprintln!("Failed to open link in browser, please visit it manually."),
            }

            let poll_interval = std::time::Duration::from_secs(login.poll_interval);
            loop {
                let response = client.get(&login.verification_url).send().unwrap();
                if response.status() == reqwest::StatusCode::OK {
                    break response.json::<Login>().unwrap();
                } else {
                    match response.json::<Error>().unwrap() {
                        // Login token expired
                        Error { errno: 126, .. } => {}
                        error => error.fail(),
                    }
                }
                std::thread::sleep(poll_interval);
            }
        },
        |token| {
            let response = client
                .get(&format!("{}/vpn/account", BASE_URL))
                .bearer_auth(token)
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

    let mut action_performed = false;
    if matches.is_present("print-token") {
        action_performed = true;
        println!("{}", login.token);
    }

    let mut rng = rand::thread_rng();

    match matches.subcommand() {
        ("device", Some(device_m)) => match device_m.subcommand() {
            ("add", Some(sub_m)) => {
                let pubkey = sub_m.value_of("pubkey").map_or_else(
                    || private_to_public_key(sub_m.value_of("privkey").unwrap()).unwrap(),
                    |pubkey| pubkey.to_owned(),
                );
                print_device(
                    &NewDevice {
                        name: sub_m
                            .value_of("name")
                            .unwrap_or(&sys_info::hostname().unwrap()),
                        pubkey: &pubkey,
                    }
                    .upload(&client, &login.token),
                );
            }
            ("list", ..) => {
                for device in login.user.devices {
                    print_device(&device);
                }
            }
            ("remove", Some(sub_m)) => {
                for id in sub_m.values_of("ids").unwrap() {
                    for device in login.user.devices.iter().filter(|device| {
                        id == device.name
                            || id == device.pubkey
                            || private_to_public_key(id)
                                .map_or(false, |pubkey| pubkey == device.pubkey)
                    }) {
                        client
                            .delete(&format!(
                                "{}/vpn/device/{}",
                                BASE_URL,
                                percent_encoding::utf8_percent_encode(
                                    &device.pubkey,
                                    percent_encoding::NON_ALPHANUMERIC
                                )
                            ))
                            .bearer_auth(&login.token)
                            .send()
                            .unwrap();
                    }
                }
            }
            _ => unreachable!(),
        },
        ("relay", Some(relay_m)) => {
            match relay_m.subcommand() {
                ("list", ..) => {
                    for country in ServerList::new(client, &login.token).countries {
                        println!("{} ({})", country.name, country.code);
                        for city in country.cities {
                            println!(
                                "\t{} ({}) @ {}°N, {}°W",
                                city.name, city.code, city.latitude, city.longitude
                            );
                            for server in city.servers {
                                println!(
                                    "\t\t{} ({}, {})",
                                    server.hostname, server.ipv4_addr_in, server.ipv6_addr_in
                                );
                            }
                        }
                    }
                }
                ("save", Some(save_m)) => {
                    let (pubkey_base64, privkey_base64) = save_m.value_of("privkey").map_or_else(
                        || {
                            let privkey = StaticSecret::new(&mut rand::rngs::OsRng);
                            let privkey_base64 = base64::encode(privkey.to_bytes());
                            (
                                base64::encode(PublicKey::from(&privkey).as_bytes()),
                                privkey_base64,
                            )
                        },
                        |privkey_base64| {
                            (
                                private_to_public_key(privkey_base64).unwrap(),
                                privkey_base64.to_owned(),
                            )
                        },
                    );
                    let (ipv4_address, ipv6_address) = login
                        .user
                        .devices
                        .iter()
                        .find(|device| device.pubkey == pubkey_base64)
                        .map_or_else(
                            || {
                                eprintln!("Public key not in device list, uploading it.");
                                let device = NewDevice {
                                    name: save_m
                                        .value_of("name")
                                        .unwrap_or(&sys_info::hostname().unwrap()),
                                    pubkey: &pubkey_base64,
                                }
                                .upload(&client, &login.token);
                                (device.ipv4_address, device.ipv6_address)
                            },
                            |device| (device.ipv4_address.clone(), device.ipv6_address.clone()),
                        );

                    let re = regex::Regex::new(save_m.value_of("regex").unwrap()).unwrap();
                    let server_list = ServerList::new(client, &login.token);
                    let filtered = server_list
                        .countries
                        .iter()
                        .flat_map(|country| {
                            country.cities.iter().flat_map(|city| city.servers.iter())
                        })
                        .filter(|server| re.is_match(&server.hostname));
                    for server in if let Some(limit) =
                        NonZeroUsize::new(save_m.value_of("limit").unwrap().parse().unwrap())
                    {
                        filtered.choose_multiple(&mut rng, limit.get())
                    } else {
                        filtered.collect()
                    } {
                        let output = format!(
                            "[Interface]
PrivateKey = {}
Address = {},{}
DNS = {},

[Peer]
PublicKey = {}
AllowedIPs = 0.0.0.0/0,::0/0
Endpoint = {}:{}\n",
                            privkey_base64,
                            ipv4_address,
                            ipv6_address,
                            server.ipv4_gateway,
                            server.public_key,
                            server.ipv4_addr_in,
                            // Deal with ranges
                            {
                                let mut ports =
                                    server.port_ranges.iter().map(|(from, to)| (*from)..=(*to));
                                let port_arg = save_m.value_of("port").unwrap();
                                if port_arg == "random" {
                                    ports.flatten().choose(&mut rng).unwrap()
                                } else {
                                    let port = port_arg.parse().unwrap();
                                    if ports.any(|range| range.contains(&port)) {
                                        port
                                    } else {
                                        println!("{} is outside of the usable port range.", port);
                                        std::process::exit(2);
                                    }
                                }
                            }
                        );
                        match save_m.value_of("output").unwrap() {
                            "-" => {
                                print!("{}", output);
                            }
                            path => {
                                let path = std::path::Path::new(path);
                                if path.is_dir() {
                                    let mut file = std::fs::File::create(
                                        path.join(format!("{}.conf", server.hostname)),
                                    )
                                    .unwrap();
                                    file.write(output.as_bytes()).unwrap();
                                } else {
                                    let mut file = std::fs::File::create(path).unwrap();
                                    file.write(output.as_bytes()).unwrap();
                                }
                            }
                        }
                    }
                }
                _ => unreachable!(),
            }
        }
        _ => {
            if !action_performed {
                app().print_help().unwrap();
            }
        }
    };
}

// TODO: implement Display or whatever
fn print_device(device: &Device) {
    let Device {
        name,
        pubkey,
        ipv4_address,
        ipv6_address,
    } = device;
    println!("{}: {}, {},{}", name, pubkey, ipv4_address, ipv6_address);
}
