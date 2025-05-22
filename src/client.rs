use aya::maps::{Map, MapData};
use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use eyre::Context;

fn main() -> eyre::Result<()> {
    // let map_data = MapData::from_pin("/sys/fs/bpf/tc/globals/availability")
    //     .context("Availability map not found")?;
    // let availability_map = aya::maps::Array::<MapData, u32>::try_from(Map::Array(map_data))?;
    // let server = availability_map
    //     .iter()
    //     .take(service)
    //     .filter_map(flatten)
    //     .enumerate()
    //     .min_by_key(|(_, v)| *v)
    //     .map(|(i, _)| i)
    //     .unwrap_or(0);
    let mut stream = TcpStream::connect(("192.168.2.79", 8080))?;
    stream.write_all(b"Request")?;
    stream.flush()?;
    stream.shutdown(Shutdown::Write)?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;
    println!("{}", String::from_utf8_lossy(&buf));
    
    Ok(())
}
