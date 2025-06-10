use bytecodec::{ByteCount, Decode, Eos};
use eyre::ensure;
use httpcodec::{NoBodyDecoder, RequestDecoder};
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
use std::thread::sleep;
use std::time::Duration;
use std::{cmp, thread};

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

fn handle(stream: TcpeHandle, send: Arc<Mutex<TransportSender>>) -> eyre::Result<()> {
    println!("handling");
    let mut stream = BufReader::new(stream);
    let mut decoder = RequestDecoder::<NoBodyDecoder>::default();
    let mut head = Vec::new();
    let mut buf = [0; 1024];
    let item = loop {
        let mut size = match decoder.requiring_bytes() {
            ByteCount::Finite(n) => cmp::min(n, buf.len() as u64) as usize,
            ByteCount::Infinite => buf.len(),
            ByteCount::Unknown => 1,
        };
        println!("required bytes {size:?}");
        let eos = if size != 0 {
            size = stream.read(&mut buf[..size])?;
            Eos::new(size == 0)
        } else {
            Eos::new(false)
        };
        // decoder.omit()

        let consumed = decoder.decode(&buf[..size], eos)?;
        head.extend_from_slice(&buf[..consumed]);
        if decoder.is_idle() {
            let item = decoder.finish_decoding()?;
            break item;
        }
    };
    println!("{item:?}");
    // TODO decision here

    println!("starting handoff to server");
    head.extend_from_slice(stream.buffer());
    println!("{:?}", String::from_utf8_lossy(&head));
    let mut stream = stream.into_inner();
    let connection_id = stream.connection_id();
    handoff_start(connection_id, head)?;

    println!("advertise server path");
    stream.advertise((SERVER_IP, SERVER_PORT2).into(), 9, send.clone())?;
    println!("removing lb path");
    stream.close_path((SERVER_IP, SERVER_PORT).into(), send.clone())?;

    println!("ending handoff to server");
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;

    if let Err(e) = handoff_end(connection_id, buf) {
        eprintln!("Error handing off, continuing as a pass through load balancer: {e:?}");
        // TODO
    } else {
        println!("closing connection");
        sleep(Duration::from_millis(100));
        stream.shutdown(Shutdown::Both)?;
    }

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
