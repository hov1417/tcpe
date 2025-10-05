use bytecodec::{ByteCount, Decode, Eos};
use eyre::ensure;
use httpcodec::{NoBodyDecoder, RequestDecoder};
use mpdsr::handoff::{TcpeHandoffEnd, TcpeHandoffStart};
use mpdsr::LB_PORT;
use mpdsr::SERVER_IP;
use mpdsr::SERVER_PORT2;
use mpdsr::{raw_tcp_socket, SERVER_PORT1};
use mpdsr::{TcpeHandle, HANDOFF_PORT1};
use mpdsr::{TcpeServer, HANDOFF_PORT2};
use oxhttp::model::{Body, Method, Request, StatusCode};
use oxhttp::Client;
use pnet::transport::TransportSender;
use rand::random;
use std::io::{BufReader, Read, Write};
use std::net::{Shutdown, SocketAddr, SocketAddrV4, TcpStream};
use std::sync::{Arc, Mutex};
use std::{cmp, io, thread};

fn main() -> eyre::Result<()> {
    let raw_send = raw_tcp_socket()?;
    let raw_send = Arc::new(Mutex::new(raw_send));
    let listen = TcpeServer::bind((SERVER_IP, LB_PORT).into())?;
    loop {
        let stream = match listen.accept() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("{e:?}");
                continue
            },
        };
        let raw_send = raw_send.clone();
        thread::spawn(move || {
            if let Err(e) = handle(stream, raw_send) {
                eprintln!("Error: {e:?}");
            }
        });
    }
}

#[derive(Debug, Clone, Copy)]
struct Server {
    addr: SocketAddr,
    handoff_addr: SocketAddr,
}
const SERVERS: [Server; 2] = [
    Server {
        addr: SocketAddr::V4(SocketAddrV4::new(SERVER_IP, SERVER_PORT1)),
        handoff_addr: SocketAddr::V4(SocketAddrV4::new(SERVER_IP, HANDOFF_PORT1)),
    },
    Server {
        addr: SocketAddr::V4(SocketAddrV4::new(SERVER_IP, SERVER_PORT2)),
        handoff_addr: SocketAddr::V4(SocketAddrV4::new(SERVER_IP, HANDOFF_PORT2)),
    },
];

fn handle(stream: TcpeHandle, send: Arc<Mutex<TransportSender>>) -> eyre::Result<()> {
    let mut stream = BufReader::new(stream);
    let mut decoder = RequestDecoder::<NoBodyDecoder>::default();
    let mut head = Vec::new();
    let mut buf = [0; 1024];
    loop {
        let mut size = match decoder.requiring_bytes() {
            ByteCount::Finite(n) => cmp::min(n, buf.len() as u64) as usize,
            ByteCount::Infinite => buf.len(),
            ByteCount::Unknown => 1,
        };
        let eos = if size != 0 {
            size = stream.read(&mut buf[..size])?;
            Eos::new(size == 0)
        } else {
            Eos::new(false)
        };

        let consumed = decoder.decode(&buf[..size], eos)?;
        head.extend_from_slice(&buf[..consumed]);
        if decoder.is_idle() {
            let item = decoder.finish_decoding()?;
            break item;
        }
    };
    head.extend_from_slice(stream.buffer());
    let mut client_stream = stream.into_inner();
    let connection_id = client_stream.connection_id();
    let server = loop {
        let i = random::<u8>() % SERVERS.len() as u8;
        let server = SERVERS[i as usize];
        if let Err(e) = handoff_start(server.handoff_addr, connection_id, &head) {
            eprintln!(
                "Error while handing off start, continuing as a pass through load balancer: {e:?}"
            );
            continue;
        }
        break server;
    };

    client_stream.advertise(server.addr, 9, send.clone())?;
    client_stream.close_path((SERVER_IP, LB_PORT).into(), send.clone())?;

    let mut buf = Vec::new();
    client_stream.read_to_end(&mut buf)?;

    if let Err(e) = handoff_end(server.handoff_addr, connection_id, &buf) {
        eprintln!("Error handing off, continuing as a pass through load balancer: {e:?}");
        let mut server_con = TcpStream::connect(server.addr)?;
        server_con.write_all(&head)?;
        server_con.write_all(&buf)?;
        io::copy(&mut server_con, &mut client_stream)?;
    }
    client_stream.shutdown(Shutdown::Both)?;

    Ok(())
}

fn handoff_start(server: SocketAddr, connection_id: u32, current_data: &[u8]) -> eyre::Result<()> {
    let client = Client::new();
    let server_url = format!("http://{server}");
    let response = client.request(
        Request::builder()
            .uri(format!("{server_url}/handoff-start"))
            .method(Method::POST)
            .body(Body::from(serde_json::to_vec(&TcpeHandoffStart {
                connection_id,
                current_data: current_data.to_owned(),
            })?))?,
    )?;
    ensure!(response.status() == StatusCode::OK);

    Ok(())
}

fn handoff_end(server: SocketAddr, connection_id: u32, left_over_data: &[u8]) -> eyre::Result<()> {
    let client = Client::new();
    let server_url = format!("http://{server}");
    let response = client.request(
        Request::builder()
            .uri(format!("{server_url}/handoff-end"))
            .method(Method::POST)
            .body(Body::from(serde_json::to_vec(&TcpeHandoffEnd {
                connection_id,
                left_over_data: left_over_data.to_owned(),
            })?))?,
    )?;
    ensure!(response.status() == StatusCode::OK);

    Ok(())
}
