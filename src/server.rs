use mpdsr::raw_tcp_socket;
use mpdsr::TcpeHandle;
use mpdsr::TcpeServer;
use mpdsr::SERVER_IP;
use mpdsr::SERVER_PORT;
use mpdsr::SERVER_PORT2;
use pnet::transport::TransportSender;
use std::io::{Read, Write};
use std::net::Shutdown;
use std::sync::{Arc, Mutex};
use std::thread;
use std::thread::sleep;
use std::time::Duration;

fn main() -> eyre::Result<()> {
    let raw_send = raw_tcp_socket()?;
    let raw_send = Arc::new(Mutex::new(raw_send));
    let mut listen = TcpeServer::bind((SERVER_IP, SERVER_PORT).into())?;
    listen.listen_also((SERVER_IP, SERVER_PORT2).into())?;
    loop {
        let stream = listen.accept()?;
        let raw_send = raw_send.clone();
        thread::spawn(move || {
            if let Err(e) = handle(stream, raw_send) {
                println!("Error: {e:?}");
            }
        });
    }
}

fn handle(mut stream: TcpeHandle, send: Arc<Mutex<TransportSender>>) -> eyre::Result<()> {
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;
    println!("{}", String::from_utf8_lossy(&buf));

    stream.advertise((SERVER_IP, SERVER_PORT2).into(), 9, send.clone())?;
    stream.write_all(b"hello\n")?;
    stream.close_path((SERVER_IP, SERVER_PORT).into(), send.clone())?;
    stream.shutdown(Shutdown::Write)?;

    // after closing the original, we wait it to reconnect
    sleep(Duration::from_millis(100));
    stream.write_all(b"hello world")?;
    stream.close_path((SERVER_IP, SERVER_PORT2).into(), send.clone())?;

    stream.shutdown(Shutdown::Write)?;
    Ok(())
}
