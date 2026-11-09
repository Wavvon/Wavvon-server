pub mod afk_worker;
pub mod apps;
pub mod attachments;
pub mod auth;
pub mod ban_evasion;
pub mod banlist_worker;
pub mod bootstrap;
pub mod capabilities;
pub mod cert_revocation_worker;
pub mod cert_worker;
pub mod db;
pub mod dm_worker;
pub mod embedded_pg;
pub mod farm_siblings;
pub mod federation;
pub mod lan;
pub mod listen;
pub mod outgoing_webhooks;
pub mod permissions;
pub use wavvon_rate_limit as rate_limit;
pub mod reminder_worker;
pub mod retention_worker;
pub mod routes;
pub mod search;
pub mod server;
pub mod settings;
pub mod setup;
pub mod state;
pub mod sticker_image;
pub mod subkey_revocation_worker;
pub mod temp_channel_worker;
pub mod voice_loss;
pub mod voice_wt;
pub mod web_client;
pub mod webhook_url;

/// Whether `ip` is in Cloudflare's published proxy ranges: a record proxied
/// there passes HTTP and WebSockets but drops the UDP voice runs on.
// ponytail: Cloudflare's list as published (cloudflare.com/ips); it changes
// rarely, and a stale entry costs one missed --doctor warning.
pub fn udp_dropping_proxy(ip: std::net::IpAddr) -> bool {
    const V4: &[(u32, u8)] = &[
        (0xADF5_3000, 20), // 173.245.48.0/20
        (0x6715_F400, 22), // 103.21.244.0/22
        (0x6716_C800, 22), // 103.22.200.0/22
        (0x671F_0400, 22), // 103.31.4.0/22
        (0x8D65_4000, 18), // 141.101.64.0/18
        (0x6CA2_C000, 18), // 108.162.192.0/18
        (0xBE5D_F000, 20), // 190.93.240.0/20
        (0xBC72_6000, 20), // 188.114.96.0/20
        (0xC5EA_F000, 22), // 197.234.240.0/22
        (0xC629_8000, 17), // 198.41.128.0/17
        (0xA29E_0000, 15), // 162.158.0.0/15
        (0x6810_0000, 13), // 104.16.0.0/13
        (0x6818_0000, 14), // 104.24.0.0/14
        (0xAC40_0000, 13), // 172.64.0.0/13
        (0x8300_4800, 22), // 131.0.72.0/22
    ];
    const V6: &[(u128, u8)] = &[
        (0x2400_cb00 << 96, 32),
        (0x2606_4700 << 96, 32),
        (0x2803_f800 << 96, 32),
        (0x2405_b500 << 96, 32),
        (0x2405_8100 << 96, 32),
        (0x2a06_98c0 << 96, 29),
        (0x2c0f_f248 << 96, 32),
    ];
    match ip {
        std::net::IpAddr::V4(v4) => {
            let a = u32::from(v4);
            V4.iter()
                .any(|&(net, len)| a >> (32 - len) == net >> (32 - len))
        }
        std::net::IpAddr::V6(v6) => {
            let a = u128::from(v6);
            V6.iter()
                .any(|&(net, len)| a >> (128 - len) == net >> (128 - len))
        }
    }
}

#[cfg(test)]
mod proxy_range_tests {
    use super::udp_dropping_proxy;

    #[test]
    fn cloudflare_addresses_are_recognised_and_others_are_not() {
        for ip in ["104.16.1.1", "172.67.200.3", "2606:4700::6810:84e5"] {
            assert!(udp_dropping_proxy(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["8.8.8.8", "104.32.0.1", "2001:db8::1"] {
            assert!(!udp_dropping_proxy(ip.parse().unwrap()), "{ip}");
        }
    }
}
