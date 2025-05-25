use aya::maps::{HashMap, Map, MapData, MapError};
use eyre::Context;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};

pub const SERVER_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 2, 79));
pub const SERVER_PORT: u16 = 8080;

pub fn get_connection_id(
    local_sock: SocketAddr,
    remote_sock: SocketAddr,
) -> eyre::Result<Option<u32>> {
    let map_data = MapData::from_pin("/sys/fs/bpf/tc/globals/tcpe_conn_map")
        .context("tcpe_conn_map map not found")?;
    let conn_map = HashMap::<MapData, [u8; 12], u32>::try_from(Map::HashMap(map_data))?;
    let connection_id = conn_map
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

pub fn get_sock_key(tcp_stream: &TcpStream) -> io::Result<[u8; 12]> {
    let local = tcp_stream.local_addr()?;
    let remote = tcp_stream.peer_addr()?;
    get_addr_key(local, remote)
}

pub fn get_addr_key(local: SocketAddr, remote: SocketAddr) -> io::Result<[u8; 12]> {
    Ok(get_key(
        local.ip(),
        local.port(),
        remote.ip(),
        remote.port(),
    ))
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

pub fn serialize_addr(ip: IpAddr, port: u16) -> [u8; 6] {
    let IpAddr::V4(ip) = ip else {
        panic!("AAAAAAAAAAA!!!!!!!!!")
    };
    let mut res = [0_u8; 6];
    res[0..4].copy_from_slice(&ip.to_bits().to_be_bytes());
    res[4..6].copy_from_slice(&port.to_be_bytes());

    res
}
