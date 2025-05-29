use mpdsr::{TcpeHandle, SERVER_IP};
use std::io::{Read, Write};
use std::net::Shutdown;

fn main() -> eyre::Result<()> {
    let mut stream = TcpeHandle::connect((SERVER_IP, 8080).into())?;
    println!("{stream:#?}");

    stream.write_all(b"Request")?;

    // stream.new_stream()

    let addr = stream.remote_paths();
    println!("{addr:#?}");

    stream.shutdown(Shutdown::Write)?;

    let addr = stream.remote_paths();
    println!("{addr:#?}");

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;

    let addr = stream.remote_paths();
    println!("{addr:#?}");

    println!("{}", String::from_utf8_lossy(&buf));


    Ok(())
}
