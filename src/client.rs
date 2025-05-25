use eyre::{bail, Context};
use mpdsr::{get_connection_id, SERVER_IP};
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use std::io;
use std::io::Read;
use std::io::{ErrorKind, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::os::fd::AsFd;
use std::sync::{Arc, Mutex};

// TODO: error handling
fn read_first(streams: &mut [TcpStream], buf: &mut [u8]) -> io::Result<usize> {
    let mut poll_fds: Vec<PollFd> = streams
        .iter()
        .map(|s| PollFd::new(s.as_fd(), PollFlags::POLLIN))
        .collect();

    // Block until at least one socket becomes readable
    poll(&mut poll_fds, PollTimeout::NONE)?;

    for (i, pfd) in poll_fds.iter().enumerate() {
        if pfd
            .revents()
            .unwrap_or(PollFlags::empty())
            .contains(PollFlags::POLLIN)
        {
            let n = streams[i].read(buf)?;
            return Ok(n);
        }
    }
    unreachable!("poll returned but no fd was ready");
}

struct TCPEReaderInner {
    connection_id: u32,
    streams: Vec<TcpStream>,
}

#[derive(Clone)]
struct TCPEClient {
    inner: Arc<Mutex<TCPEReaderInner>>,
}

impl TCPEClient {
    pub fn connect(remote_sock: SocketAddr) -> eyre::Result<Self> {
        let initial_stream =
            TcpStream::connect(remote_sock).context("Error connecting to remote server")?;
        let connection_id = get_connection_id(initial_stream.local_addr()?, remote_sock)
            .context("Error reading connection id")?;
        let Some(connection_id) = connection_id else {
            bail!("Connection ID not found, not a TCPE server")
        };

        Ok(TCPEClient {
            inner: Arc::new(Mutex::new(TCPEReaderInner {
                connection_id,
                streams: vec![initial_stream],
            })),
        })
    }

    pub fn shutdown(&self, shutdown: Shutdown) -> io::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        for s in inner.streams.iter_mut() {
            s.shutdown(shutdown.clone())?;
        }
        Ok(())
    }
}

impl Write for TCPEClient {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut client = self.inner.lock().map_err(|_| ErrorKind::BrokenPipe)?;
        let mut written = 0;
        let mut stream_index = 0;
        for (i, s) in client.streams.iter_mut().enumerate() {
            match s.write(buf) {
                Ok(w) => {
                    written = w;
                    stream_index = i;
                }
                Err(e)
                    if e.kind() == ErrorKind::BrokenPipe
                        || e.kind() == ErrorKind::ConnectionReset =>
                {
                    // this stream is broken, trying a new one
                    continue;
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }
        if stream_index != 0 {
            client.streams.drain(0..(stream_index - 1));
        }

        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Read for TCPEClient {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut client = self.inner.lock().map_err(|_| ErrorKind::BrokenPipe)?;
        read_first(&mut client.streams, buf)
    }
}

fn main() -> eyre::Result<()> {
    let mut stream = TCPEClient::connect((SERVER_IP, 8080).into())?;

    stream.write_all(b"Request")?;

    stream.shutdown(Shutdown::Write)?;

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;

    println!("{}", String::from_utf8_lossy(&buf));

    Ok(())
}
