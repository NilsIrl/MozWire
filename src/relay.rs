use crate::constants::RELAYLIST_URL;
use serde::de;
use std::{
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
};

struct PublicKeyVisitor;

impl de::Visitor<'_> for PublicKeyVisitor {
    type Value = PublicKey;
    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str(
            "INVALID DATA RETURNED FROM SERVER POSSIBLE ATTEMPT AT EXPLOINTING SOMETHING",
        )
    }

    fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
        let mut pubkey = [0; 32];
        base64::decode_config_slice(v, base64::STANDARD, &mut pubkey).unwrap();
        Ok(PublicKey(x25519_dalek::PublicKey::from(pubkey)))
    }
}

impl<'de> serde::Deserialize<'de> for PublicKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_bytes(PublicKeyVisitor)
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&base64::encode(self.0.as_bytes()))
    }
}

pub struct PublicKey(x25519_dalek::PublicKey);

// weight and include_in_country omitted
#[derive(serde::Deserialize)]
pub struct Relay {
    pub hostname: String,
    pub ipv4_addr_in: Ipv4Addr,
    ipv6_addr_in: Ipv6Addr,
    pub public_key: PublicKey,
    pub multihop_port: u16,
}

impl Relay {
    fn validate_hostname(&self) -> bool {
        self.hostname
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
    }
}

// latitude and longitude omitted
#[derive(serde::Deserialize)]
struct City {
    name: String,
    code: String,
    latitude: f64,
    longitude: f64,
    relays: Vec<Relay>,
}

#[derive(serde::Deserialize)]
struct Country {
    name: String,
    code: String,
    cities: Vec<City>,
}

#[derive(serde::Deserialize)]
pub struct RelayList {
    countries: Vec<Country>,
}

impl RelayList {
    pub fn new(client: reqwest::blocking::Client) -> Self {
        let server_list = client
            .get(RELAYLIST_URL)
            .send()
            .unwrap()
            .json::<RelayList>()
            .unwrap();
        if let Some(server) = server_list
            .countries
            .iter()
            .flat_map(|country| country.cities.iter().flat_map(|city| city.relays.iter()))
            .find(|server| !server.validate_hostname())
        {
            eprintln!(
                "A server contains invalid characters in its hostname: {}",
                server.hostname
            );
            std::process::exit(3);
        }
        server_list
    }

    pub fn servers(&self) -> impl Iterator<Item = &Relay> {
        self.countries
            .iter()
            .flat_map(|country| country.cities.iter().flat_map(|city| city.relays.iter()))
    }
}

impl fmt::Display for RelayList {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for country in &self.countries {
            writeln!(f, "{} ({})", country.name, country.code)?;
            for city in &country.cities {
                writeln!(
                    f,
                    "\t{} ({}) @ {}°N, {}°W",
                    city.name, city.code, city.latitude, city.longitude
                )?;
                for server in &city.relays {
                    writeln!(
                        f,
                        "\t\t{} ({}, {})",
                        server.hostname, server.ipv4_addr_in, server.ipv6_addr_in
                    )?;
                }
            }
        }
        Ok(())
    }
}
