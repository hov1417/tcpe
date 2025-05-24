use aya::maps::{Map, MapData, MapError};
use eyre::Context;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

pub const SERVER_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 2, 79));
pub const SERVER_PORT: u16 = 8080;

pub fn set_connection_id_3(local_ip: IpAddr, remote_sock: SocketAddr) -> eyre::Result<()> {
    let map_data = MapData::from_pin("/sys/fs/bpf/tcpe_egress_map_3")
        .context("tcpe_egress_map_3 map not found")?;
    let mut map = aya::maps::HashMap::<MapData, [u8; 10], u32>::try_from(Map::HashMap(map_data))?;
    let connection_id: u32 = 5423;
    map.insert(
        get_key_3(
            local_ip,
            remote_sock.ip(),
            remote_sock.port(),
        ),
        connection_id,
        0,
    )?;
    Ok(())
}

// pub fn set_connection_id(local_sock: SocketAddr, remote_sock: SocketAddr) -> eyre::Result<()> {
//     let map_data = MapData::from_pin("/sys/fs/bpf/tcpe_egress_map_3")
//         .context("tcpe_egress_map_3 map not found")?;
//     let mut map = aya::maps::HashMap::<MapData, [u8; 10], u32>::try_from(Map::HashMap(map_data))?;
//     let connection_id: u32 = 5423;
//     map.insert(
//         get_key(
//             local_sock.ip(),
//             local_sock.port(),
//             remote_sock.ip(),
//             remote_sock.port(),
//         ),
//         connection_id,
//         0,
//     )?;
//     Ok(())
// }

pub fn get_connection_id(
    local_sock: SocketAddr,
    remote_sock: SocketAddr,
) -> eyre::Result<Option<u32>> {
    println!("local_sock {local_sock:?}");
    println!("remote_sock {remote_sock:?}");
    let map_data = MapData::from_pin("/sys/fs/bpf/tcp_extension_ingress_map")
        .context("tcp_extension_ingress_map map not found")?;
    let availability_map =
        aya::maps::HashMap::<MapData, [u8; 12], u32>::try_from(Map::HashMap(map_data))?;
    let connection_id = availability_map
        .get(
            &get_key(
                local_sock.ip(),
                local_sock.port(),
                remote_sock.ip(),
                remote_sock.port(),
            ),
            0,
        )
        .map(Some)
        .or_else(|e| match e {
            MapError::KeyNotFound => Ok(None),
            e => Err(e),
        })?;
    Ok(connection_id)
}

pub fn get_key(local_ip: IpAddr, local_port: u16, remote_ip: IpAddr, remote_port: u16) -> [u8; 12] {
    let (IpAddr::V4(remote_ip), IpAddr::V4(local_ip)) = (remote_ip, local_ip) else {
        panic!("AAAAAAAAAAA!!!!!!!!!")
    };
    let mut res = [0_u8; 12];
    res[0..4].copy_from_slice(&remote_ip.to_bits().to_be_bytes());
    res[4..8].copy_from_slice(&local_ip.to_bits().to_be_bytes());
    res[8..10].copy_from_slice(&remote_port.to_be_bytes());
    res[10..12].copy_from_slice(&local_port.to_be_bytes());

    res
}

pub fn get_key_3(local_ip: IpAddr, remote_ip: IpAddr, remote_port: u16) -> [u8; 10] {
    let (IpAddr::V4(remote_ip), IpAddr::V4(local_ip)) = (remote_ip, local_ip) else {
        panic!("AAAAAAAAAAA!!!!!!!!!")
    };
    let mut res = [0_u8; 10];
    res[0..4].copy_from_slice(&remote_ip.to_bits().to_be_bytes());
    res[4..8].copy_from_slice(&local_ip.to_bits().to_be_bytes());
    res[8..10].copy_from_slice(&remote_port.to_be_bytes());

    res
}
