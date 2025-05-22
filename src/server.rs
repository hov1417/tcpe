use aya::maps::{Map, MapData};
use eyre::Context;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};

const MY_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 2, 79));
const MY_PORT: u16 = 8080;

fn main() {
    let listen = TcpListener::bind((MY_IP, MY_PORT)).unwrap();
    loop {
        let (stream, sock) = listen.accept().unwrap();
        if let Err(e) = handle(stream, sock) {
            println!("Error: {}", e);
        }
    }
}

fn handle(mut stream: TcpStream, sock: SocketAddr) -> eyre::Result<()> {
    let map_data = MapData::from_pin("/sys/fs/bpf/tcp_extension_egress_map")
        .context("tcp_extension_egress_map map not found")?;
    let mut availability_map =
        aya::maps::HashMap::<MapData, [u8; 12], u32>::try_from(Map::HashMap(map_data))?;
    let connection_id: u32 = 5423;
    availability_map.insert(
        get_key(sock.ip(), sock.port(), MY_IP, MY_PORT),
        connection_id,
        0,
    )?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;
    println!("{}", String::from_utf8_lossy(&buf));
    stream.write_all(b"hello world")?;
    Ok(())
}

fn get_key(remote_ip: IpAddr, remote_port: u16, local_ip: IpAddr, local_port: u16) -> [u8; 12] {
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
