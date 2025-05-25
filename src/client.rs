use aya::maps::{HashMap, Map, MapData, MapError};
use eyre::{bail, eyre, Context};
use mpdsr::{get_addr_key, get_connection_id, get_sock_key, serialize_addr, SERVER_IP};
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use std::io;
use std::io::{Error, Read};
use std::io::{ErrorKind, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4, TcpStream};
use std::ops::Deref;
use std::os::fd::AsFd;
use std::sync::{Arc, Mutex, MutexGuard};

pub fn get_new_path(
    local_sock: SocketAddr,
    remote_sock: SocketAddr,
) -> eyre::Result<Option<SocketAddr>> {
    let map_data = MapData::from_pin("/sys/fs/bpf/tc/globals/tcpe_path_map")
        .context("tcpe_path_map map not found")?;
    let mut map = HashMap::<MapData, [u8; 12], [u8; 8]>::try_from(Map::HashMap(map_data))?;
    let key = get_addr_key(local_sock, remote_sock)?;
    let data = map.get(&key, 0).map(Some).or_else(|e| match e {
        MapError::KeyNotFound => Ok(None),
        e => Err(e),
    })?;
    if let Some(data) = data {
        let address = Ipv4Addr::from_bits(u32::from_be_bytes((&data[0..4]).try_into().unwrap()));
        let port = u16::from_be_bytes((&data[4..6]).try_into().unwrap());
        map.remove(&key)?;
        Ok(Some(SocketAddr::V4(SocketAddrV4::new(address, port))))
    } else {
        Ok(None)
    }
}

// TODO: error handling
fn read_first(client: &mut MutexGuard<TcpeReaderInner>, buf: &mut [u8]) -> io::Result<usize> {
    let streams = &mut client.streams;
    let mut poll_fds: Vec<PollFd> = streams
        .iter()
        .map(|s| PollFd::new(s.as_fd(), PollFlags::POLLIN | PollFlags::POLLERR))
        .collect();

    // Block until at least one socket becomes readable
    poll(&mut poll_fds, PollTimeout::NONE)?;

    for (i, pfd) in poll_fds.iter().enumerate() {
        let flags = pfd.revents().unwrap_or(PollFlags::empty());
        if flags.contains(PollFlags::POLLIN) {
            let n = streams[i].tcp.read(buf)?;

            let local_addr = streams[i].local_addr()?;
            let peer_addr = streams[i].peer_addr;
            let tcpe_path =
                get_new_path(local_addr, peer_addr).map_err(|e| Error::new(ErrorKind::Other, e))?;
            client.local_paths.extend(tcpe_path.into_iter());
            return Ok(n);
        } else if flags.contains(PollFlags::POLLERR) {
            println!("closed vonc vor");
        }
    }
    unreachable!("poll returned but no fd was ready");
}

struct TcpeStream {
    tcp: TcpStream,
    peer_addr: SocketAddr,
}

impl Deref for TcpeStream {
    type Target = TcpStream;

    fn deref(&self) -> &Self::Target {
        &self.tcp
    }
}

struct TcpeReaderInner {
    connection_id: u32,
    streams: Vec<TcpeStream>,
    remote_paths: Vec<SocketAddr>,
    remote_paths_to_send: Vec<SocketAddr>,
    local_paths: Vec<SocketAddr>,
}

#[derive(Clone)]
struct TcpeClient {
    inner: Arc<Mutex<TcpeReaderInner>>,
}

impl TcpeClient {
    pub fn connect(remote_sock: SocketAddr) -> eyre::Result<Self> {
        let initial_stream =
            TcpStream::connect(remote_sock).context("Error connecting to remote server")?;
        let connection_id = get_connection_id(initial_stream.local_addr()?, remote_sock)
            .context("Error reading connection id")?;
        let Some(connection_id) = connection_id else {
            bail!("Connection ID not found, not a Tcpe server")
        };

        Ok(TcpeClient {
            inner: Arc::new(Mutex::new(TcpeReaderInner {
                connection_id,
                remote_paths_to_send: vec![],
                local_paths: vec![initial_stream.local_addr()?],
                remote_paths: vec![remote_sock],
                streams: vec![TcpeStream {
                    tcp: initial_stream,
                    peer_addr: remote_sock,
                }],
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

    fn register_path_for_socket(tcp_stream: &TcpStream, new_path: SocketAddr) -> eyre::Result<()> {
        let map_data = MapData::from_pin("/sys/fs/bpf/tcpe_new_path_map")
            .context("tcpe_new_path_map map not found")?;
        let mut map = HashMap::<MapData, [u8; 12], [u8; 6]>::try_from(Map::HashMap(map_data))?;
        let key = get_sock_key(tcp_stream)?;
        map.insert(&key, serialize_addr(new_path.ip(), new_path.port()), 0)
            .context("Error registering Tcpe path")?;
        Ok(())
    }

    // register new path, and advertise on next packet sent
    pub fn register(&self, new_path: SocketAddr) -> eyre::Result<()> {
        let mut client = self.inner.lock().map_err(|_| eyre!("Poisoned"))?;
        client.remote_paths_to_send.push(new_path);
        Ok(())
    }

    // register new path, and advertise immediately with empty packet
    pub fn advertise(&mut self, new_path: SocketAddr) -> eyre::Result<()> {
        self.register(new_path)?;
        self.write(&[])?;
        Ok(())
    }

    fn write(
        client: &mut MutexGuard<TcpeReaderInner>,
        buf: &[u8],
        new_path: Option<SocketAddr>,
    ) -> io::Result<usize> {
        let mut stream_index = 0;
        let mut written = 0;
        for (i, s) in client.streams.iter_mut().enumerate() {
            if let Some(p) = new_path {
                Self::register_path_for_socket(s, p)
                    .map_err(|e| Error::new(ErrorKind::Other, e))?;
            }
            match s.tcp.write(buf) {
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
}

impl Write for TcpeClient {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut client = self.inner.lock().map_err(|_| ErrorKind::BrokenPipe)?;

        let new_path = client.remote_paths_to_send.pop();
        let write = Self::write(&mut client, buf, new_path);

        if write.is_err() {
            client.remote_paths_to_send.extend(new_path.into_iter())
        }

        write
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Read for TcpeClient {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut client = self.inner.lock().map_err(|_| ErrorKind::BrokenPipe)?;
        read_first(&mut client, buf)
    }
}

fn main() -> eyre::Result<()> {
    let mut stream = TcpeClient::connect((SERVER_IP, 8080).into())?;

    stream.write_all(b"Request")?;

    stream.shutdown(Shutdown::Write)?;

    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;

    println!("{}", String::from_utf8_lossy(&buf));

    Ok(())
}
