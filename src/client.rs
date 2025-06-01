use mpdsr::{TcpeHandle, SERVER_IP};
use std::io::{Read, Write};
use std::net::Shutdown;
use std::thread::sleep;
use std::time::Duration;

fn main() -> eyre::Result<()> {
    let mut stream = TcpeHandle::connect((SERVER_IP, 8080).into())?;
    println!("Sending request");
    stream.write_all(
        b"Request first line based on which Server should decide the real server\n\
              Data content which is only would be used in the real server\n",
    )?;
    sleep(Duration::from_millis(100));

    stream.write_all(b"Data after some time\n")?;

    sleep(Duration::from_millis(100));
    stream.write_all(b"End of data\n")?;

    sleep(Duration::from_millis(100));
    stream.shutdown(Shutdown::Write)?;
    
    println!("Reading response");

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;

    println!("{}", String::from_utf8_lossy(&buf));

    Ok(())
}
