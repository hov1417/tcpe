use mpdsr::{TcpeServer, TcpeStream, SERVER_IP, SERVER_PORT};
use std::io::Read;

fn main() -> eyre::Result<()> {
    let listen = TcpeServer::bind((SERVER_IP, SERVER_PORT).into())?;
    loop {
        let stream = listen.accept()?;
        if let Err(e) = handle(stream) {
            println!("Error: {}", e);
        }
    }
}

fn handle(mut stream: TcpeStream) -> eyre::Result<()> {
    // let local_sock = stream.local_addr()?;
    // set_connection_id(local_sock, remote_sock)?;

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;
    println!("{}", String::from_utf8_lossy(&buf));

    // stream.write_all(b"hello world")?;

    Ok(())
}
