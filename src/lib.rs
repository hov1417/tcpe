use aya::maps::{HashMap, Map, MapData, MapError};
use eyre::{bail, eyre, Context};
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use std::io;
use std::io::{Error, ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::ops::Deref;
use std::os::fd::{AsFd, AsRawFd, FromRawFd};
use std::sync::{Arc, Mutex};

pub const SERVER_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 2, 79));
pub const SERVER_PORT: u16 = 8080;

pub fn get_connection_id(
    client_sock: SocketAddr,
    server_sock: SocketAddr,
) -> eyre::Result<Option<u32>> {
    let map_data = MapData::from_pin("/sys/fs/bpf/tc/globals/tcpe_conn_map")
        .context("tcpe_conn_map map not found")?;
    let conn_map = HashMap::<MapData, [u8; 12], u32>::try_from(Map::HashMap(map_data))?;
    let connection_id = conn_map
        .get(
            &get_key(
                client_sock.ip(),
                client_sock.port(),
                server_sock.ip(),
                server_sock.port(),
            ),
            0,
        )
        .map(Some)
        .or_else(|e| match e {
            MapError::KeyNotFound => Ok(None),
            e => Err(e),
        })?;
    Ok(connection_id)
}

pub fn get_sock_key_client(tcp_stream: &TcpStream) -> io::Result<[u8; 12]> {
    let client = tcp_stream.local_addr()?;
    let server = tcp_stream.peer_addr()?;
    get_addr_key(client, server)
}

pub fn get_sock_key_server(tcp_stream: &TcpStream) -> io::Result<[u8; 12]> {
    let client = tcp_stream.peer_addr()?;
    let server = tcp_stream.local_addr()?;
    get_addr_key(client, server)
}

pub fn get_addr_key(client: SocketAddr, server: SocketAddr) -> io::Result<[u8; 12]> {
    Ok(get_key(
        client.ip(),
        client.port(),
        server.ip(),
        server.port(),
    ))
}

pub fn get_key(
    client_ip: IpAddr,
    client_port: u16,
    server_ip: IpAddr,
    server_port: u16,
) -> [u8; 12] {
    let (IpAddr::V4(server_ip), IpAddr::V4(client_ip)) = (server_ip, client_ip) else {
        panic!("AAAAAAAAAAA!!!!!!!!!")
    };
    let mut res = [0_u8; 12];
    res[0..4].copy_from_slice(&server_ip.to_bits().to_be_bytes());
    res[4..8].copy_from_slice(&client_ip.to_bits().to_be_bytes());
    res[8..10].copy_from_slice(&server_port.to_be_bytes());
    res[10..12].copy_from_slice(&client_port.to_be_bytes());

    res
}

pub fn serialize_addr(ip: IpAddr, port: u16) -> [u8; 6] {
    let IpAddr::V4(ip) = ip else {
        panic!("AAAAAAAAAAA!!!!!!!!!")
    };
    let mut res = [0_u8; 6];
    res[0..4].copy_from_slice(&ip.to_bits().to_be_bytes());
    res[4..6].copy_from_slice(&port.to_be_bytes());

    res
}

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
fn read_first(client: &mut TcpeStream, buf: &mut [u8]) -> io::Result<usize> {
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

fn register_path_for_socket(
    tcp_stream: &TcpStream,
    new_path: SocketAddr,
    is_server: bool,
) -> eyre::Result<()> {
    let map_data = MapData::from_pin("/sys/fs/bpf/tcpe_new_path_map")
        .context("tcpe_new_path_map map not found")?;
    let mut map = HashMap::<MapData, [u8; 12], [u8; 6]>::try_from(Map::HashMap(map_data))?;
    let key = if is_server {
        get_sock_key_server(tcp_stream)?
    } else {
        get_sock_key_client(tcp_stream)?
    };
    map.insert(&key, serialize_addr(new_path.ip(), new_path.port()), 0)
        .context("Error registering Tcpe path")?;
    Ok(())
}

#[derive(Debug)]
struct TcpStreamWrapper {
    tcp: TcpStream,
    peer_addr: SocketAddr,
}

impl Deref for TcpStreamWrapper {
    type Target = TcpStream;

    fn deref(&self) -> &Self::Target {
        &self.tcp
    }
}

#[derive(Debug)]
pub struct TcpeStream {
    connection_id: u32,
    is_server: bool,
    streams: Vec<TcpStreamWrapper>,
    remote_paths: Vec<SocketAddr>,
    remote_paths_to_send: Vec<SocketAddr>,
    local_paths: Vec<SocketAddr>,
}

impl TcpeStream {
    pub fn connect(remote_sock: SocketAddr) -> eyre::Result<Self> {
        let initial_stream =
            TcpStream::connect(remote_sock).context("Error connecting to remote server")?;
        let connection_id = get_connection_id(initial_stream.local_addr()?, remote_sock)
            .context("Error reading connection id")?;
        let Some(connection_id) = connection_id else {
            bail!("Connection ID not found, not a Tcpe server")
        };

        Ok(TcpeStream {
            connection_id,
            is_server: false,
            remote_paths_to_send: vec![],
            local_paths: vec![initial_stream.local_addr()?],
            remote_paths: vec![remote_sock],
            streams: vec![TcpStreamWrapper {
                tcp: initial_stream,
                peer_addr: remote_sock,
            }],
        })
    }

    fn from_stream(tcp: TcpStream, connection_id: u32, is_server: bool) -> eyre::Result<Self> {
        let peer_addr = tcp.peer_addr()?;
        Ok(TcpeStream {
            connection_id,
            is_server,
            remote_paths_to_send: vec![],
            local_paths: vec![tcp.local_addr()?],
            remote_paths: vec![peer_addr],
            streams: vec![TcpStreamWrapper { tcp, peer_addr }],
        })
    }

    pub fn shutdown(&mut self, shutdown: Shutdown) -> io::Result<()> {
        for s in self.streams.iter_mut() {
            s.shutdown(shutdown.clone())?;
        }
        Ok(())
    }

    /// register new path, and advertise on next packet sent
    pub fn register(&mut self, new_path: SocketAddr) -> eyre::Result<()> {
        self.remote_paths_to_send.push(new_path);
        Ok(())
    }

    /// register new path, and advertise immediately with empty packet
    pub fn advertise(&mut self, new_path: SocketAddr) -> eyre::Result<()> {
        self.register(new_path)?;
        self.write(&[])?;
        Ok(())
    }

    fn write_and_notify(&mut self, buf: &[u8], new_path: Option<SocketAddr>) -> io::Result<usize> {
        let mut stream_index = 0;
        let mut written = 0;
        for (i, s) in self.streams.iter_mut().enumerate() {
            if let Some(p) = new_path {
                register_path_for_socket(s, p, self.is_server)
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
            self.streams.drain(0..(stream_index - 1));
        }
        Ok(written)
    }
}

impl Write for TcpeStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let new_path = self.remote_paths_to_send.pop();
        let write = self.write_and_notify(buf, new_path);

        if write.is_err() {
            self.remote_paths_to_send.extend(new_path.into_iter())
        }

        write
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Read for TcpeStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        read_first(self, buf)
    }
}

#[derive(Clone, Debug)]
pub struct TcpeClient {
    inner: Arc<Mutex<TcpeStream>>,
}

impl TcpeClient {
    pub fn connect(remote_sock: SocketAddr) -> eyre::Result<Self> {
        Ok(TcpeClient {
            inner: Arc::new(Mutex::new(TcpeStream::connect(remote_sock)?)),
        })
    }

    pub fn shutdown(&self, shutdown: Shutdown) -> io::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        inner.shutdown(shutdown)
    }

    /// register new path, and advertise on next packet sent
    pub fn register(&self, new_path: SocketAddr) -> eyre::Result<()> {
        let mut client = self.inner.lock().map_err(|_| eyre!("Poisoned"))?;
        client.register(new_path)
    }

    /// register new path, and advertise immediately with empty packet
    pub fn advertise(&mut self, new_path: SocketAddr) -> eyre::Result<()> {
        self.register(new_path)?;
        self.write(&[])?;
        Ok(())
    }
}

impl Write for TcpeClient {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut client = self.inner.lock().map_err(|_| ErrorKind::BrokenPipe)?;
        client.write(buf)
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

// TODO: error handling
fn listen_first(sockets: &[TcpListener]) -> io::Result<TcpStream> {
    let mut poll_fds: Vec<PollFd> = sockets
        .iter()
        .map(|s| PollFd::new(s.as_fd(), PollFlags::POLLIN))
        .collect();

    // Block until at least one socket becomes readable
    poll(&mut poll_fds, PollTimeout::NONE)?;

    for pfd in poll_fds.iter() {
        let flags = pfd.revents().unwrap_or(PollFlags::empty());
        if flags.contains(PollFlags::POLLIN) {
            let lfd = pfd.as_fd();

            let conn_fd = nix::sys::socket::accept(lfd.as_raw_fd())?;
            return Ok(unsafe { TcpStream::from_raw_fd(conn_fd) });
        }
    }
    unreachable!("poll returned but no fd was ready");
}

pub struct TcpeServer {
    listeners: Vec<TcpListener>,
}

impl TcpeServer {
    pub fn bind(sock: SocketAddr) -> eyre::Result<Self> {
        let inner = TcpListener::bind(sock)?;
        Ok(Self {
            listeners: vec![inner],
        })
    }

    pub fn accept(&self) -> eyre::Result<TcpeStream> {
        let stream = listen_first(&self.listeners)?;
        let server_sock = stream.local_addr()?;
        let client_sock = stream.peer_addr()?;
        let connection_id = get_connection_id(client_sock, server_sock)?;
        let Some(connection_id) = connection_id else {
            bail!("Connection ID not found");
        };
        TcpeStream::from_stream(stream, connection_id, true)
    }
}
