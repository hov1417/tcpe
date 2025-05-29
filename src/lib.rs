use aya::maps::{HashMap as AyaHashMap, Map, MapData, MapError};
use dashmap::DashMap;
use eyre::{bail, eyre, Context, ContextCompat};
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use pnet::packet::{ipv4::checksum as ip_checksum, tcp::ipv4_checksum};
use pnet::transport::{transport_channel, TransportChannelType, TransportSender};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::MutableIpv4Packet;
use pnet_packet::tcp::{MutableTcpPacket, TcpFlags, TcpOption, TcpOptionNumber};
use std::collections::HashMap;
use std::ffi::c_int;
use std::io::{Error, ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::ops::Deref;
use std::os::fd::{AsFd, AsRawFd, FromRawFd};
use std::sync::{Arc, LazyLock, Mutex};
use std::{io, mem, thread};

pub const SERVER_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 2, 79));
pub const SERVER_PORT: u16 = 8080;
pub const SERVER_PORT2: u16 = 8081;

pub fn get_connection_id(
    client_sock: SocketAddr,
    server_sock: SocketAddr,
) -> eyre::Result<Option<u32>> {
    let map_data = MapData::from_pin("/sys/fs/bpf/tc/globals/tcpe_conn_map")
        .context("tcpe_conn_map map not found")?;
    let conn_map = AyaHashMap::<MapData, [u8; 12], u32>::try_from(Map::HashMap(map_data))?;
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

pub fn serialize_addr(ip: IpAddr, port: u16) -> [u8; 8] {
    let IpAddr::V4(ip) = ip else {
        panic!("AAAAAAAAAAA!!!!!!!!!")
    };
    let mut res = [0_u8; 8];
    res[0..4].copy_from_slice(&ip.to_bits().to_be_bytes());
    res[4..6].copy_from_slice(&port.to_be_bytes());

    res
}

pub fn get_new_path(
    local_sock: SocketAddr,
    remote_sock: SocketAddr,
    is_server: bool,
) -> eyre::Result<Option<SocketAddr>> {
    let map_data = MapData::from_pin("/sys/fs/bpf/tc/globals/tcpe_path_map")
        .context("tcpe_path_map map not found")?;
    let mut map = AyaHashMap::<MapData, [u8; 12], [u8; 8]>::try_from(Map::HashMap(map_data))?;
    let key = if is_server {
        get_addr_key(remote_sock, local_sock)?
    } else {
        get_addr_key(local_sock, remote_sock)?
    };
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
fn read_first(stream: &mut TcpeStream, buf: &mut [u8]) -> io::Result<usize> {
    let streams = &mut stream.streams;
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
            check_new_paths(stream, local_addr, peer_addr)?;
            return Ok(n);
        } else if flags.contains(PollFlags::POLLERR) {
            println!("closed vonc vor");
        }
    }
    unreachable!("poll returned but no fd was ready");
}

fn check_new_paths(
    tcpe_stream: &mut TcpeStream,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
) -> Result<(), Error> {
    let tcpe_path = get_new_path(local_addr, peer_addr, tcpe_stream.is_server)
        .map_err(|e| Error::new(ErrorKind::Other, e))?;
    tcpe_stream.remote_paths.extend(tcpe_path.into_iter());
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
    local_paths: Vec<SocketAddr>,
}

pub fn check(t: libc::c_int) -> io::Result<libc::c_int> {
    if t != 0 {
        Err(Error::last_os_error())
    } else {
        Ok(t)
    }
}
pub fn setsockopt<T>(
    sock: c_int,
    level: c_int,
    option_name: c_int,
    option_value: T,
) -> io::Result<()> {
    unsafe {
        check(libc::setsockopt(
            sock,
            level,
            option_name,
            (&raw const option_value) as *const _,
            mem::size_of::<T>() as libc::socklen_t,
        ))?;
        Ok(())
    }
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
            local_paths: vec![initial_stream.local_addr()?],
            remote_paths: vec![remote_sock],
            streams: vec![TcpStreamWrapper {
                tcp: initial_stream,
                peer_addr: remote_sock,
            }],
        })
    }

    pub fn new_stream(&mut self, remote_sock: SocketAddr) -> eyre::Result<bool> {
        let registered_sock = self
            .remote_paths
            .iter()
            .filter(|s| **s == remote_sock)
            .next()
            .is_some();

        if registered_sock {
            let stream = TcpStream::connect(remote_sock)?;
            self.streams.push(TcpStreamWrapper {
                tcp: stream,
                peer_addr: remote_sock,
            });
        }

        Ok(registered_sock)
    }

    fn from_stream(tcp: TcpStream, connection_id: u32, is_server: bool) -> eyre::Result<Self> {
        let peer_addr = tcp.peer_addr()?;
        Ok(TcpeStream {
            connection_id,
            is_server,
            local_paths: vec![tcp.local_addr()?],
            remote_paths: vec![peer_addr],
            streams: vec![TcpStreamWrapper { tcp, peer_addr }],
        })
    }

    pub fn shutdown(&mut self, shutdown: Shutdown) -> io::Result<()> {
        for s in self.streams.iter_mut() {
            // let new_path = self.registered_paths_to_send.pop();
            // println!("{new_path:?}");
            let res = s.shutdown(shutdown.clone());
            // set_notify_new_path(new_path, s, self.is_server)?;
            // if res.is_err() {
            // self.registered_paths_to_send.extend(new_path.into_iter());
            // }
            res?;
        }
        Ok(())
    }

    /// advertise new path
    pub fn advertise(
        &mut self,
        new_path: SocketAddr,
        send: Arc<Mutex<TransportSender>>,
    ) -> eyre::Result<()> {
        // self.registered_paths_to_send.push(new_path);

        let stream = &self.streams[0];

        let new_path_option = new_path_option(new_path);
        send_option(send, stream, new_path_option)?;
        Ok(())
    }

    pub fn remote_paths(&self) -> Vec<SocketAddr> {
        self.remote_paths.clone()
    }

    fn write_to_first_stream(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut stream_index = 0;
        let mut written = 0;
        for (i, s) in self.streams.iter_mut().enumerate() {
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

const TCPE_KIND: u8 = 254;
const TCPE_NEW_PATH: u16 = 1418;
fn new_path_option(new_path: SocketAddr) -> TcpOption {
    let mut data = Vec::new();
    // struct tcpe_new_path
    // {
    //     __u8 kind; /* 254 */
    //     __u8 len; /* 12 */
    //     __u16 magic; /* 1418 */
    //     __u32 address;
    //     __u16 port;
    //     __u16 padd;
    // };
    data.extend_from_slice(&TCPE_NEW_PATH.to_be_bytes()); // magic
    data.extend_from_slice(&ipv4(new_path.ip()).to_bits().to_be_bytes()); // address
    data.extend_from_slice(&new_path.port().to_be_bytes()); // port
    data.extend_from_slice(&[0u8; 2]); // padding

    TcpOption {
        number: TcpOptionNumber(TCPE_KIND),
        length: vec![12],
        data,
    }
}

fn send_option(
    send: Arc<Mutex<TransportSender>>,
    stream: &TcpStreamWrapper,
    option: TcpOption,
) -> eyre::Result<()> {
    let seq_num = *SEQ_NUMS
        .get(&(stream.local_addr()?, stream.peer_addr))
        .context("unknown seq num")?
        .value();

    let src_addr = ipv4(stream.local_addr()?.ip());
    let dest_addr = ipv4(stream.peer_addr.ip());
    sent_empty_packet(send, stream, seq_num, src_addr, dest_addr, option)?;
    Ok(())
}

fn sent_empty_packet(
    send: Arc<Mutex<TransportSender>>,
    stream: &TcpStreamWrapper,
    seq_num: u32,
    src_addr: Ipv4Addr,
    dest_addr: Ipv4Addr,
    option: TcpOption,
) -> eyre::Result<()> {
    let mut send = send.lock().map_err(|_| eyre!("Poisoned"))?;
    let ack_n = 0;

    // Build one IPv4 + TCP header, no payload ------------------------------
    const IPV4_LEN: usize = 20;
    let option_len = 1 + option.length.len() + option.data.len();
    let tcp_len = 20 + option_len;
    let len: usize = IPV4_LEN + tcp_len;
    let mut buf = vec![0u8; len];

    // TCP -------------------------------------------------------------------
    {
        let mut tcp = MutableTcpPacket::new(&mut buf[IPV4_LEN..]).unwrap();
        tcp.set_source(stream.local_addr()?.port());
        tcp.set_destination(stream.peer_addr.port());
        tcp.set_sequence(seq_num);
        tcp.set_acknowledgement(ack_n);
        tcp.set_data_offset((tcp_len >> 2) as u8);
        tcp.set_flags(TcpFlags::ACK);
        tcp.set_window(500);
        tcp.set_options(&[option]);
    }
    // IPv4 ------------------------------------------------------------------
    {
        let mut ip = MutableIpv4Packet::new(&mut buf[..IPV4_LEN]).unwrap();
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length(len as u16);
        ip.set_ttl(64);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip.set_source(src_addr);
        ip.set_destination(dest_addr);
        ip.set_checksum(ip_checksum(&ip.to_immutable()));
    }

    // TCP checksum (needs pseudo-header) ------------------------------------
    {
        let mut tcp = MutableTcpPacket::new(&mut buf[IPV4_LEN..]).unwrap();

        let csum = ipv4_checksum(&tcp.to_immutable(), &dest_addr, &src_addr);
        tcp.set_checksum(csum);
    }

    send.send_to(&MutableIpv4Packet::new(&mut buf).unwrap(), dest_addr.into())?;
    Ok(())
}

fn ipv4(ip: IpAddr) -> Ipv4Addr {
    if let IpAddr::V4(ip) = ip {
        ip
    } else {
        unreachable!("A")
    }
}

impl Write for TcpeStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_to_first_stream(buf)
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
pub struct TcpeHandle {
    inner: Arc<Mutex<TcpeStream>>,
}

impl TcpeHandle {
    pub fn connect(remote_sock: SocketAddr) -> eyre::Result<Self> {
        Ok(TcpeHandle {
            inner: Arc::new(Mutex::new(TcpeStream::connect(remote_sock)?)),
        })
    }

    pub fn new_stream(&self, remote_sock: SocketAddr) -> eyre::Result<bool> {
        let mut inner = self.inner.lock().map_err(|_| eyre!("Poisoned"))?;
        inner.new_stream(remote_sock)
    }

    pub fn shutdown(&self, shutdown: Shutdown) -> io::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        inner.shutdown(shutdown)
    }

    /// register new path, and advertise on next packet sent
    pub fn register(
        &self,
        new_path: SocketAddr,
        send: Arc<Mutex<TransportSender>>,
    ) -> eyre::Result<()> {
        let mut client = self.inner.lock().map_err(|_| eyre!("Poisoned"))?;
        client.advertise(new_path, send)
    }

    // /// register new path, and advertise immediately with empty packet
    // pub fn advertise(&mut self, new_path: SocketAddr) -> eyre::Result<()> {
    //     self.register(new_path)?;
    //     Ok(())
    // }

    pub fn remote_paths(&self) -> eyre::Result<Vec<SocketAddr>> {
        let mut inner = self.inner.lock().map_err(|_| eyre!("Poisoned"))?;
        let addresses = inner
            .streams
            .iter()
            .map(|s| (s.local_addr().unwrap(), s.peer_addr))
            .collect::<Vec<_>>();
        for (l, p) in addresses {
            check_new_paths(&mut inner, l, p)?
        }
        Ok(inner.remote_paths())
    }

    fn add_stream(&mut self, tcp_stream: TcpStream) -> eyre::Result<()> {
        let mut inner = self.inner.lock().map_err(|_| eyre!("Poisoned"))?;
        inner.streams.push(TcpStreamWrapper {
            peer_addr: tcp_stream.peer_addr()?,
            tcp: tcp_stream,
        });
        Ok(())
    }
}

impl Write for TcpeHandle {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut client = self.inner.lock().map_err(|_| ErrorKind::BrokenPipe)?;
        client.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Read for TcpeHandle {
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
    connections: HashMap<u32, TcpeHandle>,
}

impl TcpeServer {
    pub fn bind(sock: SocketAddr) -> eyre::Result<Self> {
        let inner = TcpListener::bind(sock)?;
        Ok(Self {
            listeners: vec![inner],
            connections: HashMap::new(),
        })
    }

    pub fn listen_also(&mut self, socket_addr: SocketAddr) -> eyre::Result<()> {
        let listener = TcpListener::bind(socket_addr)?;
        self.listeners.push(listener);
        Ok(())
    }

    pub fn accept(&mut self) -> eyre::Result<TcpeStream> {
        let stream = listen_first(&self.listeners)?;
        let server_sock = stream.local_addr()?;
        let client_sock = stream.peer_addr()?;
        let connection_id = get_connection_id(client_sock, server_sock)?;
        let Some(connection_id) = connection_id else {
            bail!("Connection ID not found");
        };
        if let Some(state) = self.connections.get_mut(&connection_id) {
            state.add_stream(stream)?;
            return self.accept();
        }
        let stream = TcpeStream::from_stream(stream, connection_id, true)?;

        // for s in self.listeners.iter() {
        //     let addr = s.local_addr()?;
        //     if addr != server_sock {
        //         stream.advertise(addr)?;
        //     }
        // }

        Ok(stream)
    }
}

const BUFFER_SIZE: usize = 4096;

pub static SEQ_NUMS: LazyLock<DashMap<(SocketAddr, SocketAddr), u32>> =
    LazyLock::new(|| DashMap::new());

pub fn raw_tcp_socket() -> eyre::Result<TransportSender> {
    use pnet::datalink::{self, Channel, Config};
    use pnet::packet::{
        ethernet::{EtherTypes, EthernetPacket},
        ip::IpNextHeaderProtocols,
        ipv4::Ipv4Packet,
        tcp::TcpPacket,
        Packet,
    };

    // pick the interface you really use
    let iface = datalink::interfaces()
        .into_iter()
        .find(|i| i.name == "wlp59s0")
        .expect("no interface wlp59s0");

    let (_tx, rx) = match datalink::channel(&iface, Config::default())? {
        Channel::Ethernet(tx, rx) => (tx, rx),
        _ => unreachable!(),
    };

    println!("sniffing on {}", iface.name);

    thread::spawn(move || {
        let mut rx = rx;
        // let mut iter = ipv4_packet_iter(&mut rx);
        loop {
            let frame = rx.next().unwrap();
            let Some(eth) = EthernetPacket::new(frame) else {
                continue;
            };
            if eth.get_ethertype() != EtherTypes::Ipv4 {
                continue;
            }
            let Some(packet) = Ipv4Packet::new(eth.payload()) else {
                continue;
            };
            if packet.get_next_level_protocol() != IpNextHeaderProtocols::Tcp {
                continue;
            }
            let Some(tcp_packet) = TcpPacket::new(packet.payload()) else {
                continue;
            };
            if tcp_packet.get_source() == SERVER_PORT
                || tcp_packet.get_source() == SERVER_PORT2
                || tcp_packet.get_destination() == SERVER_PORT
                || tcp_packet.get_destination() == SERVER_PORT2
            {
                SEQ_NUMS
                    .entry((
                        (packet.get_source(), tcp_packet.get_source()).into(),
                        (packet.get_destination(), tcp_packet.get_destination()).into(),
                    ))
                    .insert(tcp_packet.get_sequence());
            }
        }
    });

    let protocol = TransportChannelType::Layer3(IpNextHeaderProtocols::Tcp);
    let (tx, _rx) =
        transport_channel(BUFFER_SIZE, protocol).expect("Failed to create transport channel");
    Ok(tx)
}
