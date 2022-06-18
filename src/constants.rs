use std::net::Ipv4Addr;

pub const RELAYLIST_URL: &str = "https://api.mullvad.net/public/relays/wireguard/v1/";
pub const BASE_URL: &str = "https://vpn.mozilla.org";
pub const V1_API: &str = "/api/v1";
pub const V2_API: &str = "/api/v2";
pub const IPV4_GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 64, 0, 1);
pub const PORT_RANGES: [(u16, u16); 5] = [
    (53, 53),
    (123, 123),
    (4000, 33433),
    (33565, 51820),
    (52000, 60000),
];
pub const EXPLOITATION_ATTEMPT_MESSAGE: &str = "INVALID DATA RETURNED FROM SERVER, THE CONTENT \
                                                COULD HAVE BEEN TEMPERED IN AN ATTEMPT AT \
                                                EXPLOITING VULNERABILITIES";

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(serde::Deserialize)]
    struct Wireguard {
        port_ranges: Vec<(u16, u16)>,
        ipv4_gateway: Ipv4Addr,
    }

    #[derive(serde::Deserialize)]
    struct Relays {
        wireguard: Wireguard,
    }

    #[test]
    #[ignore]
    fn test_ipv4_gateway() {
        let relays: Relays = reqwest::blocking::get("https://api.mullvad.net/app/v1/relays")
            .unwrap()
            .json()
            .unwrap();
        assert_eq!(relays.wireguard.ipv4_gateway, IPV4_GATEWAY);
        assert_eq!(relays.wireguard.port_ranges, PORT_RANGES);
    }
}
