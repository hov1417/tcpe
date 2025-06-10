mod base64_bytes;
pub mod handoff;

use crate::handoff::{TcpeHandoffEnd, TcpeHandoffStart};
use aya::maps::{HashMap as AyaHashMap, Map, MapData, MapError};
use dashmap::{DashMap, Entry};
use eyre::{bail, eyre, Context, ContextCompat};
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use pnet::datalink;
use pnet::datalink::Channel;
use pnet::datalink::Config;
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::Packet;
use pnet::packet::{ipv4::checksum as ip_checksum, tcp::ipv4_checksum};
use pnet::transport::{transport_channel, TransportChannelType, TransportSender};
use pnet_packet::ipv4::MutableIpv4Packet;
use pnet_packet::tcp::{MutableTcpPacket, TcpFlags, TcpOption, TcpOptionNumber};
use std::collections::{HashSet, VecDeque};
use std::ffi::c_int;
use std::fmt::Debug;
use std::io::{Error, ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::ops::{Deref, DerefMut, Not};
use std::os::fd::{AsFd, AsRawFd, FromRawFd};
use std::sync::mpsc::{sync_channel, SyncSender};
use std::sync::{mpsc, Arc, LazyLock, Mutex, MutexGuard};
use std::time::Duration;
use std::{io, thread};

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
        panic!("Currently only supporting Ipv4")
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
        panic!("Currently only supporting Ipv4")
    };
    let mut res = [0_u8; 8];
    res[0..4].copy_from_slice(&ip.to_bits().to_be_bytes());
    res[4..6].copy_from_slice(&port.to_be_bytes());

    res
}

#[derive(Debug)]
struct PathNotification {
    path: SocketAddr,
    priority: u8,
    action: Action,
}

fn get_path_notifications(
    local_sock: SocketAddr,
    remote_sock: SocketAddr,
    is_server: bool,
) -> eyre::Result<Vec<PathNotification>> {
    let map_data = MapData::from_pin("/sys/fs/bpf/tc/globals/tcpe_path_map")
        .context("tcpe_path_map map not found")?;
    let mut map = AyaHashMap::<MapData, [u8; 16], [u8; 8]>::try_from(Map::HashMap(map_data))?;
    let key = if is_server {
        get_addr_key(remote_sock, local_sock)?
    } else {
        get_addr_key(local_sock, remote_sock)?
    };
    let mut result = Vec::new();
    let items = map.iter().collect::<Result<Vec<_>, _>>()?;
    for (k, data) in items {
        if k[..12].eq(&key) {
            let address = Ipv4Addr::from_bits(u32::from_be_bytes((&data[0..4]).try_into()?));
            let port = u16::from_be_bytes((&data[4..6]).try_into()?);
            let priority = data[6];
            let create = data[7];
            map.remove(&k)?;
            result.push(PathNotification {
                path: SocketAddr::V4(SocketAddrV4::new(address, port)),
                priority,
                action: if create != 0 {
                    Action::Create
                } else {
                    Action::Remove
                },
            });
        }
    }
    Ok(result)
}

fn check_new_paths(
    tcpe_stream: &mut TcpeStream,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
) -> Result<(), Error> {
    let tcpe_path = get_path_notifications(local_addr, peer_addr, tcpe_stream.is_server)
        .map_err(|e| Error::new(ErrorKind::Other, e))?;
    let tcpe_path = tcpe_path.into_iter();
    for notification in tcpe_path {
        match notification.action {
            Action::Create => {
                // if same priority exists, last notification should be in front,
                // then we use stable sort
                tcpe_stream
                    .connectable_remote_paths
                    .push_front((notification.path, notification.priority));
            }
            Action::Remove => {
                tcpe_stream
                    .connectable_remote_paths
                    .retain(|(s, _)| s != &notification.path);
                // marking related streams for removal
                tcpe_stream
                    .streams
                    .iter_mut()
                    .flat_map(|s| s.as_tcp_mut())
                    .filter(|s| s.peer_addr == notification.path)
                    .for_each(|s| {
                        s.readable = false;
                        s.writable = false;
                    })
            }
        }
    }

    tcpe_stream
        .connectable_remote_paths
        .make_contiguous()
        .sort_by_key(|x| -(x.1 as i16));

    Ok(())
}

#[derive(Debug)]
struct TcpStreamWithMeta {
    tcp: TcpStream,
    peer_addr: SocketAddr,
    readable: bool,
    writable: bool,
}

#[derive(Debug)]
struct TcpStreamMoved {
    data: VecDeque<u8>,
    channel: Option<mpsc::Receiver<Vec<u8>>>,
}

impl TcpStreamMoved {
    #[inline]
    fn is_empty(&self) -> bool {
        self.data.is_empty() && self.channel.is_none()
    }
}

impl Read for TcpStreamMoved {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.data.is_empty() {
            if let Some(ch) = self.channel.take() {
                match ch.recv_timeout(Duration::from_secs(10)) {
                    Ok(d) => {
                        self.data.extend(&d);
                        self.read(buf)
                    }
                    Err(_) => Ok(0),
                }
            } else {
                Ok(0)
            }
        } else {
            self.data.read(buf)
        }
    }
}

#[derive(Debug)]
enum TcpeStreamSubflow {
    Tcp(TcpStreamWithMeta),
    HandedOff(TcpStreamMoved),
}

impl TcpeStreamSubflow {
    fn readable(&self) -> bool {
        match self {
            TcpeStreamSubflow::Tcp(t) => t.readable,
            TcpeStreamSubflow::HandedOff(b) => !b.is_empty(),
        }
    }

    fn writable(&self) -> bool {
        match self {
            TcpeStreamSubflow::Tcp(t) => t.writable,
            TcpeStreamSubflow::HandedOff(_) => false,
        }
    }

    fn as_tcp(&self) -> Option<&TcpStreamWithMeta> {
        match self {
            TcpeStreamSubflow::Tcp(t) => Some(t),
            TcpeStreamSubflow::HandedOff(_) => None,
        }
    }

    fn as_tcp_mut(&mut self) -> Option<&mut TcpStreamWithMeta> {
        match self {
            TcpeStreamSubflow::Tcp(t) => Some(t),
            TcpeStreamSubflow::HandedOff(_) => None,
        }
    }

    fn as_read(&mut self) -> Option<&mut (impl Read + Debug)> {
        match self {
            TcpeStreamSubflow::Tcp(_) => None,
            TcpeStreamSubflow::HandedOff(d) => Some(d),
        }
    }
}

impl Deref for TcpStreamWithMeta {
    type Target = TcpStream;

    fn deref(&self) -> &Self::Target {
        &self.tcp
    }
}

impl DerefMut for TcpStreamWithMeta {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.tcp
    }
}

#[derive(Debug)]
pub struct TcpeStream {
    connection_id: u32,
    is_server: bool,
    streams: Vec<TcpeStreamSubflow>,
    /// Remote paths in order of priority, first is highest
    connectable_remote_paths: VecDeque<(SocketAddr, u8)>,
    // TODO
    // local_paths: Vec<SocketAddr>,
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
            size_of::<T>() as libc::socklen_t,
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
            // local_paths: vec![initial_stream.local_addr()?],
            connectable_remote_paths: vec![(remote_sock, 8)].into(),
            streams: vec![TcpeStreamSubflow::Tcp(TcpStreamWithMeta {
                tcp: initial_stream,
                peer_addr: remote_sock,
                readable: true,
                writable: true,
            })],
        })
    }

    pub fn new_stream(&mut self, remote_sock: SocketAddr) -> eyre::Result<bool> {
        let registered_sock = self
            .connectable_remote_paths
            .iter()
            .any(|s| s.0 == remote_sock);

        if registered_sock {
            self.new_stream_unchecked(remote_sock)?;
        }

        Ok(registered_sock)
    }

    fn new_stream_unchecked(&mut self, remote_sock: SocketAddr) -> eyre::Result<()> {
        println!("new stream");
        let pgid = get_pid_and_thread_group_id();
        store_connection_id(pgid, self.connection_id)?;
        let stream = TcpStream::connect(remote_sock)?;
        remove_connection_id(pgid)?;
        self.streams.push(TcpeStreamSubflow::Tcp(TcpStreamWithMeta {
            tcp: stream,
            peer_addr: remote_sock,
            readable: true,
            writable: true,
        }));

        Ok(())
    }

    fn from_stream(tcp: TcpStream, connection_id: u32, is_server: bool) -> eyre::Result<Self> {
        let peer_addr = tcp.peer_addr()?;
        Ok(TcpeStream {
            connection_id,
            is_server,
            // local_paths: vec![tcp.local_addr()?],
            connectable_remote_paths: VecDeque::new(),
            streams: vec![TcpeStreamSubflow::Tcp(TcpStreamWithMeta {
                tcp,
                peer_addr,
                readable: true,
                writable: true,
            })],
        })
    }

    fn handoff_start(
        tcp: TcpeHandoffStart,
        channel: mpsc::Receiver<Vec<u8>>,
    ) -> eyre::Result<Self> {
        Ok(TcpeStream {
            connection_id: tcp.connection_id,
            is_server: true,
            // local_paths: vec![],
            connectable_remote_paths: VecDeque::new(),
            streams: vec![TcpeStreamSubflow::HandedOff(TcpStreamMoved {
                data: tcp.current_data.into(),
                channel: Some(channel),
            })],
        })
    }

    pub fn shutdown(&mut self, shutdown: Shutdown) -> io::Result<()> {
        for s in self.streams.iter_mut().flat_map(|s| s.as_tcp_mut()) {
            match shutdown {
                Shutdown::Read => {
                    s.readable = false;
                }
                Shutdown::Write => {
                    s.writable = false;
                }
                Shutdown::Both => {
                    s.readable = false;
                    s.writable = false;
                }
            }
            if let Err(e) = s.shutdown(shutdown) {
                eprintln!("Shutting down caused {e:?}, skipping");
            }
        }
        Ok(())
    }

    /// advertise new path
    pub fn advertise(
        &mut self,
        new_path: SocketAddr,
        priority: u8,
        send: Arc<Mutex<TransportSender>>,
    ) -> eyre::Result<()> {
        assert!(priority <= 15, "priority should be in range 0-15");

        let Some(stream) = &self.streams.iter().flat_map(|s| s.as_tcp()).next() else {
            bail!("No TcpStream available")
        };

        let new_path_option = new_path_option(new_path, priority, Action::Create);
        send_option(send, stream, new_path_option)?;
        Ok(())
    }

    pub fn close_path(
        &mut self,
        new_path: SocketAddr,
        send: Arc<Mutex<TransportSender>>,
    ) -> eyre::Result<()> {
        let Some(stream) = &self.streams.iter().flat_map(|s| s.as_tcp()).next() else {
            bail!("No TcpStream available")
        };

        let new_path_option = new_path_option(new_path, 0, Action::Remove);
        send_option(send, stream, new_path_option)?;
        Ok(())
    }

    pub fn remote_paths(&self) -> Vec<SocketAddr> {
        self.connectable_remote_paths.iter().map(|x| x.0).collect()
    }

    fn cleanup(&mut self) {
        let mut unreachable_remotes = HashSet::new();
        self.streams.retain(|s| {
            if !s.readable() && !s.writable() {
                if let Some(s) = s.as_tcp() {
                    unreachable_remotes.insert(s.peer_addr);
                }
            }
            s.readable() || s.writable()
        });
        self.connectable_remote_paths
            .retain(|(s, _)| !unreachable_remotes.contains(s));
    }
}

fn store_connection_id(pid_tgid: u64, connection_id: u32) -> eyre::Result<()> {
    let map_data = MapData::from_pin("/sys/fs/bpf/tc/globals/connection_ids")
        .context("connection_ids map not found")?;
    let mut connection_ids = AyaHashMap::<MapData, u64, u32>::try_from(Map::HashMap(map_data))?;

    connection_ids.insert(pid_tgid, connection_id, 0)?;

    Ok(())
}

fn remove_connection_id(pid_tgid: u64) -> eyre::Result<()> {
    let map_data = MapData::from_pin("/sys/fs/bpf/tc/globals/connection_ids")
        .context("connection_ids map not found")?;
    let mut connection_ids = AyaHashMap::<MapData, u64, u32>::try_from(Map::HashMap(map_data))?;

    connection_ids.remove(&pid_tgid)?;

    Ok(())
}

fn get_pid_and_thread_group_id() -> u64 {
    let pid = unsafe { libc::getpid() };
    let pgid = unsafe { libc::getpgid(pid) };
    let pid = pid as u64;
    let pgid = pgid as u64;
    (pgid << 32) | pid
}

const TCPE_KIND: u8 = 254;
const TCPE_NEW_PATH: u16 = 1418;

#[derive(Debug)]
enum Action {
    Create,
    Remove,
}

fn new_path_option(new_path: SocketAddr, priority: u8, action: Action) -> TcpOption {
    let mut data = Vec::new();
    let action_flag = match action {
        Action::Create => 1 << 3,
        Action::Remove => 0,
    };
    data.extend_from_slice(&TCPE_NEW_PATH.to_be_bytes()); // magic
    data.extend_from_slice(&ipv4(new_path.ip()).to_bits().to_be_bytes()); // address
    data.extend_from_slice(&new_path.port().to_be_bytes()); // port
    data.extend_from_slice(&[(priority << 4) | action_flag; 1]); // priority and action
    data.extend_from_slice(&[0u8; 1]); // padding

    TcpOption {
        number: TcpOptionNumber(TCPE_KIND),
        length: vec![12],
        data,
    }
}

fn send_option(
    send: Arc<Mutex<TransportSender>>,
    stream: &TcpStreamWithMeta,
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
    stream: &TcpStreamWithMeta,
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

    send.send_to(MutableIpv4Packet::new(&mut buf).unwrap(), dest_addr.into())?;
    Ok(())
}

fn ipv4(ip: IpAddr) -> Ipv4Addr {
    if let IpAddr::V4(ip) = ip {
        ip
    } else {
        unreachable!("A")
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

    fn from_stream(s: TcpeStream) -> eyre::Result<Self> {
        Ok(TcpeHandle {
            inner: Arc::new(Mutex::new(s)),
        })
    }

    pub fn advertise(
        &self,
        new_path: SocketAddr,
        priority: u8,
        send: Arc<Mutex<TransportSender>>,
    ) -> eyre::Result<()> {
        let mut inner = self.inner.lock().map_err(|_| eyre!("Poisoned"))?;
        inner.advertise(new_path, priority, send)
    }

    pub fn close_path(
        &mut self,
        new_path: SocketAddr,
        send: Arc<Mutex<TransportSender>>,
    ) -> eyre::Result<()> {
        let mut inner = self.inner.lock().map_err(|_| eyre!("Poisoned"))?;
        inner.close_path(new_path, send)
    }

    pub fn shutdown(&self, shutdown: Shutdown) -> io::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        inner.shutdown(shutdown)
    }

    pub fn remote_paths(&self) -> eyre::Result<Vec<SocketAddr>> {
        let mut inner = self.inner.lock().map_err(|_| eyre!("Poisoned"))?;
        self.remote_paths_inner(&mut inner)
    }

    fn remote_paths_inner(
        &self,
        inner: &mut MutexGuard<TcpeStream>,
    ) -> eyre::Result<Vec<SocketAddr>> {
        Self::check_path_changes(inner)?;
        Ok(inner.remote_paths())
    }

    fn check_path_changes(inner: &mut MutexGuard<TcpeStream>) -> eyre::Result<()> {
        let addresses = inner
            .streams
            .iter()
            .flat_map(|s| s.as_tcp())
            .map(|s| (s.local_addr().unwrap(), s.peer_addr))
            .collect::<Vec<_>>();
        for (l, p) in addresses {
            check_new_paths(inner, l, p)?
        }
        Ok(())
    }

    pub fn connection_id(&self) -> u32 {
        let inner = self.inner.lock().unwrap();
        inner.connection_id
    }

    fn add_stream(&mut self, tcp_stream: TcpStream) -> eyre::Result<()> {
        let mut inner = self.inner.lock().map_err(|_| eyre!("Poisoned"))?;
        inner
            .streams
            .push(TcpeStreamSubflow::Tcp(TcpStreamWithMeta {
                peer_addr: tcp_stream.peer_addr()?,
                tcp: tcp_stream,
                readable: true,
                writable: true,
            }));
        Ok(())
    }

    fn write_to_first_stream(&self, buf: &[u8]) -> io::Result<usize> {
        let written = loop {
            let mut inner = self.inner.lock().map_err(|_| ErrorKind::BrokenPipe)?;
            {
                if inner.streams.is_empty() {
                    return Ok(0);
                }
                let remotes = self
                    .remote_paths_inner(&mut inner)
                    .map_err(|e| Error::new(ErrorKind::Other, e))?;
                if !remotes.is_empty() {
                    if let Some(s) = inner.streams[0].as_tcp() {
                        if s.peer_addr != remotes[0] {
                            inner
                                .new_stream_unchecked(remotes[0])
                                .map_err(|e| Error::new(ErrorKind::Other, e))?;
                        }
                    }
                }
                inner.cleanup();
            }

            let writable = inner
                .streams
                .iter_mut()
                .filter(|s| s.writable())
                .flat_map(|s| s.as_tcp_mut())
                .next();

            if writable.is_none() {
                println!("Empty streams");
                if inner.connectable_remote_paths.is_empty() {
                    break 0;
                }

                println!("trying new streams");
                let first_remote_path = inner.connectable_remote_paths[0].0;
                if !inner.new_stream(first_remote_path).map_err(|e| {
                    eprintln!("{e:?}");
                    ErrorKind::BrokenPipe
                })? {
                    println!("unsuccessfully new streams");
                    break 0;
                }
                continue;
            }
            let s = writable.unwrap();

            println!("writing data to {:?}", s.peer_addr);
            match s.write(buf) {
                Ok(w) => {
                    if w == 0 {
                        s.writable = false;
                        continue;
                    }
                    break w;
                }
                Err(e)
                    if e.kind() == ErrorKind::BrokenPipe
                        || e.kind() == ErrorKind::ConnectionReset =>
                {
                    eprintln!("Subflow is broken: {e:?}");
                    // this stream is broken, trying a new one
                    s.writable = false;
                    s.readable = false;
                    continue;
                }
                Err(e) => {
                    eprintln!("Error writing {e:?}");
                    return Err(e);
                }
            }
        };

        // self.cleanup();
        Ok(written)
    }
}

impl Write for TcpeHandle {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_to_first_stream(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Read for TcpeHandle {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let read = 'overall: loop {
            let mut tcpe_stream = self.inner.lock().map_err(|_| ErrorKind::BrokenPipe)?;
            {
                if tcpe_stream.streams.is_empty() {
                    return Ok(0);
                }
                let remotes = self
                    .remote_paths_inner(&mut tcpe_stream)
                    .map_err(|e| Error::new(ErrorKind::Other, e))?;
                if !remotes.is_empty() {
                    if let Some(s) = tcpe_stream.streams[0].as_tcp() {
                        if s.peer_addr != remotes[0] {
                            tcpe_stream
                                .new_stream_unchecked(remotes[0])
                                .map_err(|e| Error::new(ErrorKind::Other, e))?;
                        }
                    }
                }
                tcpe_stream.cleanup();
            }

            let existing_data = tcpe_stream
                .streams
                .iter_mut()
                .flat_map(|s| s.as_read())
                .next();
            if let Some(data) = existing_data {
                break 'overall data.read(buf)?;
            }
            let mut readables = tcpe_stream
                .streams
                .iter_mut()
                .filter(|s| s.readable())
                .flat_map(|s| s.as_tcp_mut())
                .collect::<Vec<_>>();

            if readables.is_empty() {
                println!("Empty streams closing");
                if tcpe_stream.connectable_remote_paths.is_empty() {
                    break 'overall 0;
                }

                println!("trying new streams");
                let addr = tcpe_stream.connectable_remote_paths[0].0;
                if !tcpe_stream.new_stream(addr).map_err(|e| {
                    eprintln!("{e:?}");
                    ErrorKind::BrokenPipe
                })? {
                    println!("unsuccessful new streams");
                    break 'overall 0;
                }
                continue 'overall;
            }

            let mut poll_fds: Vec<PollFd> = readables
                .iter()
                .map(|s| {
                    PollFd::new(
                        s.as_fd(),
                        PollFlags::all() & (PollFlags::POLLOUT | PollFlags::POLLWRNORM).not(),
                    )
                })
                .collect();

            let timeout: PollTimeout = Duration::from_millis(1000).try_into().unwrap();
            poll(&mut poll_fds, timeout).inspect_err(|e| {
                eprintln!("Error while polling {e:?}");
            })?;

            for (i, pfd) in poll_fds.iter().enumerate() {
                let flags = pfd.revents().unwrap_or(PollFlags::empty());

                if flags.contains(PollFlags::POLLIN) {
                    let n = match readables[i].read(buf) {
                        Ok(read) => read,
                        Err(e)
                            if e.kind() == ErrorKind::BrokenPipe
                                || e.kind() == ErrorKind::ConnectionReset =>
                        {
                            println!("Error after stream polled, retrying");
                            continue 'overall;
                        }
                        Err(e) => {
                            eprintln!("Error polling {e:?}");
                            return Err(e);
                        }
                    };
                    if n == 0 {
                        readables[i].readable = false;
                        continue 'overall;
                    }

                    let local_addr = readables[i].local_addr()?;
                    let peer_addr = readables[i].peer_addr;
                    check_new_paths(&mut tcpe_stream, local_addr, peer_addr)?;
                    break 'overall n;
                } else if !flags.is_empty() {
                    println!("Other event {:?}", flags);
                }
            }
            tcpe_stream.cleanup();
        };

        Ok(read)
    }
}

// TODO: error handling
fn accept_first(sockets: &[TcpListener]) -> io::Result<TcpStream> {
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
    connections: DashMap<u32, TcpeHandle>,
    handoff: DashMap<u32, SyncSender<Vec<u8>>>,
}

impl TcpeServer {
    pub fn bind(sock: SocketAddr) -> eyre::Result<Self> {
        let inner = TcpListener::bind(sock)?;
        Ok(Self {
            listeners: vec![inner],
            connections: DashMap::new(),
            handoff: DashMap::new(),
        })
    }

    pub fn listen_also(&mut self, socket_addr: SocketAddr) -> eyre::Result<()> {
        let listener = TcpListener::bind(socket_addr)?;
        self.listeners.push(listener);
        Ok(())
    }

    pub fn handoff_start(&self, handoff: TcpeHandoffStart) -> eyre::Result<TcpeHandle> {
        match self.connections.entry(handoff.connection_id) {
            Entry::Occupied(_) => {
                bail!("handoff connection already exists")
            }
            Entry::Vacant(v) => {
                let (sender, receiver) = sync_channel(1);
                self.handoff.insert(handoff.connection_id, sender);
                let stream = TcpeStream::handoff_start(handoff, receiver)?;
                let handle = TcpeHandle::from_stream(stream)?;
                v.insert(handle.clone());
                Ok(handle)
            }
        }
    }

    pub fn handoff_end(&self, handoff: TcpeHandoffEnd) -> eyre::Result<()> {
        if let Some((_, sender)) = self.handoff.remove(&handoff.connection_id) {
            sender.send(handoff.left_over_data)?;
            Ok(())
        } else {
            bail!("handoff connection not found");
        }
    }

    pub fn accept(&self) -> eyre::Result<TcpeHandle> {
        let stream = accept_first(&self.listeners)?;
        let server_sock = stream.local_addr()?;
        let client_sock = stream.peer_addr()?;
        let connection_id = get_connection_id(client_sock, server_sock)?;
        let Some(connection_id) = connection_id else {
            bail!("Connection ID not found");
        };
        match self.connections.entry(connection_id) {
            Entry::Occupied(mut state) => {
                state.get_mut().add_stream(stream)?;
                Ok(state.get().clone())
            }
            Entry::Vacant(v) => {
                let stream = TcpeStream::from_stream(stream, connection_id, true)?;
                let handle = TcpeHandle::from_stream(stream)?;
                v.insert(handle.clone());
                Ok(handle)
            }
        }
    }
}

const BUFFER_SIZE: usize = 4096;

pub static SEQ_NUMS: LazyLock<DashMap<(SocketAddr, SocketAddr), u32>> = LazyLock::new(DashMap::new);

pub fn raw_tcp_socket() -> eyre::Result<TransportSender> {
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
