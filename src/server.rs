use mpdsr::{raw_tcp_socket, TcpeServer, TcpeStream, SERVER_IP, SERVER_PORT, SERVER_PORT2};
use pnet::transport::TransportSender;
use std::io::{Read, Write};
use std::net::Shutdown;
use std::sync::{Arc, Mutex};

fn main() -> eyre::Result<()> {
    let raw_send = raw_tcp_socket()?;
    let raw_send = Arc::new(Mutex::new(raw_send));
    let mut listen = TcpeServer::bind((SERVER_IP, SERVER_PORT).into())?;
    listen.listen_also((SERVER_IP, SERVER_PORT2).into())?;
    loop {
        let stream = listen.accept()?;
        println!("{stream:#?}");
        if let Err(e) = handle(stream, raw_send.clone()) {
            println!("Error: {}", e);
        }
    }
}

fn handle(mut stream: TcpeStream, send: Arc<Mutex<TransportSender>>) -> eyre::Result<()> {
    // let local_sock = stream.local_addr()?;
    // set_connection_id(local_sock, remote_sock)?;

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;

    stream.advertise((SERVER_IP, SERVER_PORT2).into(), send)?;
    
    // stream.notify(send)?;

    stream.shutdown(Shutdown::Write)?;
    println!("{}", String::from_utf8_lossy(&buf));

    stream.write_all(b"hello world")?;

    Ok(())
}
