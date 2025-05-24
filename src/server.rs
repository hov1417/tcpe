use aya::maps::{Map, MapData, SockMap};
use eyre::Context;
use mpdsr::{set_connection_id, SERVER_IP, SERVER_PORT};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use aya::maps::MapType::SockMap;

fn main() -> eyre::Result<()> {
    let listen = TcpListener::bind((SERVER_IP, SERVER_PORT))?;
    loop {
        let pid_tgid = get_pid_tgid();
        println!("{pid_tgid}");
        set_connection_id(pid_tgid)?;
        let (stream, sock) = listen.accept()?;
        if let Err(e) = handle(stream, sock) {
            println!("Error: {}", e);
        }
    }
}

fn get_pid_tgid() -> u64 {
    let tid = unsafe { libc::gettid() as u64 };
    let tgid = unsafe { libc::getpid() as u64 };
    println!("{tid}");
    println!("{tgid}");
    let pid_tgid = (tid << 32) | tgid;
    pid_tgid
}

fn handle(mut stream: TcpStream, remote_sock: SocketAddr) -> eyre::Result<()> {
    let local_sock = stream.local_addr()?;
    // set_connection_id(local_sock, remote_sock)?;

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;
    println!("{}", String::from_utf8_lossy(&buf));

    stream.write_all(b"hello world")?;

    Ok(())
}
// 
// pub fn set_connection_id(pid_tgid: u64) -> eyre::Result<()> {
//     let map_data =
//         MapData::from_pin("/sys/fs/bpf/pid_to_connid").context("pid_to_connid map not found")?;
//     let mut map = aya::maps::HashMap::<MapData, u64, u32>::try_from(Map::HashMap(map_data))?;
//     let connection_id: u32 = 5423;
//     map.insert(pid_tgid, connection_id, 0)?;
// 
//     Ok(())
// }
