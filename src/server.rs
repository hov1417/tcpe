use std::env::args;
use mpdsr::SERVER_IP;
use mpdsr::{TcpeHandle, TcpeServer};
use std::io::{BufReader, Write};
use std::net::Shutdown;
use std::sync::Arc;
use std::time::Duration;

use bytecodec::bytes::{BytesEncoder, RemainingBytesDecoder};
use bytecodec::io::{IoDecodeExt, IoEncodeExt};
use bytecodec::Encode;
use eyre::{Context, Report};
use httpcodec::BodyDecoder;
use httpcodec::BodyEncoder;
use httpcodec::HttpVersion;
use httpcodec::ReasonPhrase;
use httpcodec::RequestDecoder;
use httpcodec::ResponseEncoder;
use mpdsr::handoff::{TcpeHandoffEnd, TcpeHandoffStart};
use oxhttp::model::header::CONTENT_TYPE;
use oxhttp::model::{Body, Method, Request, Response};
use oxhttp::Server;
use serde_json::json;
use std::net::Ipv4Addr;
use std::thread;
use std::thread::sleep;

fn main() -> eyre::Result<()> {
    let arguments = args().collect::<Vec<String>>();
    let server_port = arguments[1].parse::<u16>()?;
    let handoff_port = arguments[2].parse::<u16>()?;
    let server = Arc::new(TcpeServer::bind((SERVER_IP, server_port).into())?);
    spawn_handoff_communicator(server.clone(), handoff_port)?;

    loop {
        let stream = match server.accept() {
            Ok(stream) => stream,
            Err(e) => {
                eprint!("connection accept error {:?}", e);
                continue;
            }
        };
        thread::spawn(move || {
            if let Err(e) = handle(stream) {
                println!("Error: {e:?}");
            }
        });
    }
}

fn spawn_handoff_communicator(server: Arc<TcpeServer>, handoff_port: u16) -> eyre::Result<()> {
    Server::new(move |request| {
        handle_handoff(request, &server).unwrap_or_else(|e| {
            println!("Error: {e:?}");
            Response::builder()
                .header(CONTENT_TYPE, "application/json")
                .body(json!({"error": format!("{e}")}).to_string().into())
                .unwrap()
        })
    })
    .bind((Ipv4Addr::LOCALHOST, handoff_port))
    .with_global_timeout(Duration::from_secs(10))
    .with_max_concurrent_connections(128)
    .spawn()
    .context("Error spawning communicator")?;
    Ok(())
}

fn handle_handoff(
    request: &mut Request<Body>,
    server: &TcpeServer,
) -> eyre::Result<Response<Body>> {
    if request.uri().path() == "/handoff-start" && request.method() == Method::POST {
        println!("received handoff start");
        let handoff: TcpeHandoffStart =
            serde_json::from_reader(request.body_mut()).context("Invalid body")?;
        println!(
            "connection {}, data {:?}",
            handoff.connection_id,
            String::from_utf8_lossy(&handoff.current_data)
        );
        server.handoff_start(handoff)?;
        empty_response()
    } else if request.uri().path() == "/handoff-end" && request.method() == Method::POST {
        println!("received handoff end");
        let handoff: TcpeHandoffEnd =
            serde_json::from_reader(request.body_mut()).context("Invalid body")?;
        println!(
            "connection {}, data {:?}",
            handoff.connection_id,
            String::from_utf8_lossy(&handoff.left_over_data)
        );
        server.handoff_end(handoff)?;
        empty_response()
    } else {
        Response::builder()
            .status(oxhttp::model::StatusCode::NOT_FOUND)
            .body(Body::empty())
            .context("Error creating body")
    }
}

fn empty_response() -> Result<Response<Body>, Report> {
    Response::builder()
        .body(Body::empty())
        .context("Error creating body")
}

fn handle(stream: TcpeHandle) -> eyre::Result<()> {
    let mut decoder = RequestDecoder::<BodyDecoder<RemainingBytesDecoder>>::default();
    let mut stream = BufReader::new(stream);
    let req = decoder.decode_exact(&mut stream)?;
    println!("request {:?}", req);
    let request = httpcodec::Response::new(
        HttpVersion::V1_1,
        httpcodec::StatusCode::new(200)?,
        ReasonPhrase::new("OK")?,
        b"Reponse body",
    );

    let mut encoder = ResponseEncoder::new(BodyEncoder::new(BytesEncoder::new()));
    encoder.start_encoding(request)?;

    let mut stream = stream.into_inner();
    encoder.encode_all(&mut stream)?;
    stream.flush()?;

    sleep(Duration::from_millis(100));
    println!("Closing connection");
    stream.shutdown(Shutdown::Both)?;
    Ok(())
}
