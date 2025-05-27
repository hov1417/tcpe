use mpdsr::{TcpeClient, SERVER_IP};
use std::io::Write;
use std::net::Shutdown;

fn main() -> eyre::Result<()> {
    let mut stream = TcpeClient::connect((SERVER_IP, 8080).into())?;
    println!("{stream:#?}");

    stream.write_all(b"Request")?;

    stream.shutdown(Shutdown::Write)?;

    // let mut buf = Vec::new();
    // stream.read_to_end(&mut buf)?;
    // 
    // println!("{}", String::from_utf8_lossy(&buf));

    Ok(())
}
