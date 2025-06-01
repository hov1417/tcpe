use eyre::ensure;
use mpdsr::handoff::{TcpeHandoffEnd, TcpeHandoffStart};
use mpdsr::raw_tcp_socket;
use mpdsr::TcpeHandle;
use mpdsr::TcpeServer;
use mpdsr::SERVER_IP;
use mpdsr::SERVER_PORT;
use mpdsr::SERVER_PORT2;
use oxhttp::model::{Body, Method, Request, StatusCode};
use oxhttp::Client;
use pnet::transport::TransportSender;
use std::io::{BufReader, Read};
use std::net::Shutdown;
use std::sync::{Arc, Mutex};
use std::thread;
use std::thread::sleep;
use std::time::Duration;

fn main() -> eyre::Result<()> {
    let raw_send = raw_tcp_socket()?;
    let raw_send = Arc::new(Mutex::new(raw_send));
    let listen = TcpeServer::bind((SERVER_IP, SERVER_PORT).into())?;
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
    let mut buf = vec![0; 50];
    let mut read = BufReader::new(stream.clone());
    read.read_exact(&mut buf)?;
    println!("{}", String::from_utf8_lossy(&buf));
    // TODO decision here

    println!("starting handoff to server");
    let connection_id = stream.connection_id();
    buf.extend_from_slice(read.buffer());
    handoff_start(connection_id, buf)?;
    
    println!("advertise server path");
    stream.advertise((SERVER_IP, SERVER_PORT2).into(), 9, send.clone())?;
    println!("removing lb path");
    stream.close_path((SERVER_IP, SERVER_PORT).into(), send.clone())?;

    println!("ending handoff to server");
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;
    handoff_end(connection_id, buf)?;

    // TODO write direction backward compatibility code here

    println!("closing connection");
    sleep(Duration::from_millis(100));
    stream.shutdown(Shutdown::Both)?;
    Ok(())
}

fn handoff_start(connection_id: u32, current_data: Vec<u8>) -> eyre::Result<()> {
    let client = Client::new();
    let response = client.request(
        Request::builder()
            .uri("http://localhost:9090/handoff-start")
            .method(Method::POST)
            .body(Body::from(serde_json::to_vec(&TcpeHandoffStart {
                connection_id,
                current_data,
            })?))?,
    )?;
    ensure!(response.status() == StatusCode::OK);

    Ok(())
}

fn handoff_end(connection_id: u32, left_over_data: Vec<u8>) -> eyre::Result<()> {
    let client = Client::new();
    let response = client.request(
        Request::builder()
            .uri("http://localhost:9090/handoff-end")
            .method(Method::POST)
            .body(Body::from(serde_json::to_vec(&TcpeHandoffEnd {
                connection_id,
                left_over_data,
            })?))?,
    )?;
    ensure!(response.status() == StatusCode::OK);

    Ok(())
}
