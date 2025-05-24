use mpdsr::{get_connection_id, SERVER_IP};
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};

fn main() -> eyre::Result<()> {
    let remote_sock: SocketAddr = (SERVER_IP, 8080).into();
    let mut stream = TcpStream::connect(remote_sock)?;
    stream.write_all(b"Request")?;

    let connection_id = get_connection_id(stream.local_addr()?, remote_sock);
    println!("{connection_id:?}");

    stream.shutdown(Shutdown::Write)?;

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;

    let connection_id = get_connection_id(stream.local_addr()?, remote_sock);
    println!("{connection_id:?}");

    println!("{}", String::from_utf8_lossy(&buf));

    Ok(())
}
