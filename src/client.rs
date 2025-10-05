use mpdsr::{TcpeHandle, SERVER_IP};
use std::io::Write;

use bytecodec::bytes::BytesEncoder;
use bytecodec::bytes::RemainingBytesDecoder;
use bytecodec::io::IoDecodeExt;
use bytecodec::io::IoEncodeExt;
use bytecodec::Encode;
use httpcodec::{BodyDecoder, HttpVersion, ResponseDecoder};
use httpcodec::{BodyEncoder, Method, Request, RequestEncoder, RequestTarget};

fn main() -> eyre::Result<()> {
    let mut stream = bufstream::BufStream::new(TcpeHandle::connect((SERVER_IP, 8080).into())?);

    let request = Request::new(
        Method::new("GET")?,
        RequestTarget::new("/foo")?,
        HttpVersion::V1_1,
        b"Data content which is only would be used in the real server",
    );

    let mut encoder = RequestEncoder::new(BodyEncoder::new(BytesEncoder::new()));
    encoder.start_encoding(request)?;

    encoder.encode_all(&mut stream)?;
    stream.flush()?;

    let mut decoder = ResponseDecoder::<BodyDecoder<RemainingBytesDecoder>>::default();

    let response = decoder.decode_exact(&mut stream)?;

    println!("{response:?}");

    Ok(())
}
