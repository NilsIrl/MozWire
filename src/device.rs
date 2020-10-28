use crate::{
    constants::EXPLOITATION_ATTEMPT_MESSAGE,
    relay::{exploitation_attempt, PublicKey},
};
use serde::de;
use std::fmt;

fn is_ip_addr(c: char) -> bool {
    c.is_ascii_hexdigit() || c == '/' || c == '.' || c == ':'
}

pub struct IpAddrCidrVisitor;

impl de::Visitor<'_> for IpAddrCidrVisitor {
    type Value = IpAddrCIDR;
    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str(EXPLOITATION_ATTEMPT_MESSAGE)
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
        if !v.chars().all(is_ip_addr) {
            exploitation_attempt();
        }

        Ok(IpAddrCIDR(v.to_string()))
    }
}

#[derive(Clone)]
pub struct IpAddrCIDR(pub String);

impl<'de> serde::Deserialize<'de> for IpAddrCIDR {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_string(IpAddrCidrVisitor)
    }
}

impl std::ops::Deref for IpAddrCIDR {
    type Target = String;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(serde::Deserialize)]
pub struct Device {
    pub name: String,
    pub pubkey: PublicKey,
    pub ipv4_address: IpAddrCIDR,
    pub ipv6_address: IpAddrCIDR,
}

impl fmt::Display for Device {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "- {}: {}, {},{}",
            self.name, self.pubkey, self.ipv4_address.0, self.ipv6_address.0
        )
    }
}
