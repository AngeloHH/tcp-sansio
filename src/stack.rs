use std::collections::{BTreeMap, VecDeque};
use std::net::Ipv4Addr;
use std::str::FromStr;

use pyo3::exceptions::{PyKeyError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use rand_chacha::ChaCha12Rng;
use rand_core::{RngCore, SeedableRng};
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::time::Instant;
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpListenEndpoint, IpProtocol, Ipv4Packet, TcpPacket,
};

use crate::device::MemoryDevice;
use crate::{AddressInUseError, PacketError, TCPStateError};

const MINIMUM_MTU: usize = 40;
const EPHEMERAL_PORTS: u32 = 16384;
const ORPHAN_TIMEOUT_US: i64 = 120_000_000;
type Endpoint = Option<(String, u16)>;

struct Listener {
    port: u16,
    backlog: usize,
    buffer_size: usize,
    pending: Vec<SocketHandle>,
    accepted: VecDeque<u64>,
}

struct Connection {
    socket: SocketHandle,
    exposed: bool,
    send_blocked: bool,
    connecting: bool,
    saw_eof: bool,
    orphaned_at: Option<i64>,
}

#[pyclass]
pub struct Engine {
    address: Ipv4Addr,
    any_ip: bool,
    device: MemoryDevice,
    interface: Interface,
    sockets: SocketSet<'static>,
    listeners: BTreeMap<u64, Listener>,
    connections: BTreeMap<u64, Connection>,
    detached: Vec<SocketHandle>,
    now: i64,
    next_listener: u64,
    next_connection: u64,
    ports: ChaCha12Rng,
    mtu: usize,
}

#[pymethods]
impl Engine {
    #[new]
    #[pyo3(signature = (ip_address, mtu, seed, any_ip=false))]
    fn new(ip_address: &str, mtu: usize, seed: u64, any_ip: bool) -> PyResult<Self> {
        if mtu < MINIMUM_MTU {
            return Err(PyValueError::new_err(format!(
                "mtu must be at least {MINIMUM_MTU} bytes"
            )));
        }

        let address = parse_address(ip_address)?;
        let mut device = MemoryDevice::new(mtu);
        let mut configuration = Config::new(HardwareAddress::Ip);
        configuration.random_seed = seed;
        let timestamp = Instant::from_micros(0);
        let mut interface = Interface::new(configuration, &mut device, timestamp);
        interface.update_ip_addrs(|addresses| {
            addresses
                .push(IpCidr::new(IpAddress::Ipv4(address), 32))
                .expect("one IPv4 address must fit the interface");
        });
        // AnyIP accepts the prefixes routed through one of the interface's own
        // addresses. smoltcp 0.14 skips that check and accepts everything, but the
        // default route through our own address satisfies both behaviors. With the
        // IP medium the gateway is never used to send, so routing is unchanged.
        let gateway = if any_ip {
            address
        } else {
            Ipv4Addr::UNSPECIFIED
        };
        interface
            .routes_mut()
            .add_default_ipv4_route(gateway)
            .map_err(|_| PyValueError::new_err("unable to install the IPv4 route"))?;
        interface.set_any_ip(any_ip);

        Ok(Self {
            address,
            any_ip,
            device,
            interface,
            sockets: SocketSet::new(vec![]),
            listeners: BTreeMap::new(),
            connections: BTreeMap::new(),
            detached: vec![],
            now: 0,
            next_listener: 1,
            next_connection: 1,
            ports: ChaCha12Rng::seed_from_u64(seed ^ 0x5443_502d_5341_4e53),
            mtu,
        })
    }

    fn listen(&mut self, port: u16, backlog: usize, buffer_size: usize) -> PyResult<u64> {
        if port == 0 {
            return Err(PyValueError::new_err("port must be greater than zero"));
        }
        if backlog == 0 || buffer_size == 0 {
            return Err(PyValueError::new_err(
                "backlog and buffer_size must be greater than zero",
            ));
        }
        if self.port_in_use(port) {
            return Err(AddressInUseError::new_err("TCP port is already in use"));
        }

        let listener_id = self.next_listener;
        self.next_listener += 1;
        self.listeners.insert(
            listener_id,
            Listener {
                port,
                backlog,
                buffer_size,
                pending: vec![],
                accepted: VecDeque::new(),
            },
        );
        self.fill_listener(listener_id)?;
        Ok(listener_id)
    }

    fn listener_accept(&mut self, listener_id: u64) -> PyResult<Option<u64>> {
        let connection_id = self
            .listeners
            .get_mut(&listener_id)
            .ok_or_else(|| PyKeyError::new_err("unknown listener"))?
            .accepted
            .pop_front();
        if let Some(connection_id) = connection_id {
            self.connections
                .get_mut(&connection_id)
                .expect("accepted connections belong to the listener")
                .exposed = true;
        }
        self.fill_listener(listener_id)?;
        Ok(connection_id)
    }

    fn listener_close(&mut self, listener_id: u64) -> PyResult<()> {
        let listener = self
            .listeners
            .remove(&listener_id)
            .ok_or_else(|| PyKeyError::new_err("unknown listener"))?;
        for socket in listener.pending {
            self.detach(socket);
        }
        for connection_id in listener.accepted {
            let connection = self
                .connections
                .remove(&connection_id)
                .expect("queued connections belong to the listener");
            self.detach(connection.socket);
        }
        Ok(())
    }

    fn connect(
        &mut self,
        ip_address: &str,
        port: u16,
        local_port: Option<u16>,
        buffer_size: usize,
    ) -> PyResult<u64> {
        if port == 0 || local_port == Some(0) || buffer_size == 0 {
            return Err(PyValueError::new_err(
                "ports and buffer_size must be greater than zero",
            ));
        }
        let local_port = match local_port {
            Some(local_port) if !self.port_in_use(local_port) => local_port,
            Some(_) => {
                return Err(AddressInUseError::new_err(
                    "local TCP port is already in use",
                ));
            }
            None => self.ephemeral_port()?,
        };
        let remote = (IpAddress::Ipv4(parse_address(ip_address)?), port);
        let mut socket = tcp_socket(buffer_size);
        socket.set_congestion_control(tcp::CongestionControl::Cubic);
        socket
            .connect(self.interface.context(), remote, local_port)
            .map_err(|error| TCPStateError::new_err(format!("connect failed: {error}")))?;

        let connection_id = self.next_connection;
        self.next_connection += 1;
        let socket = self.sockets.add(socket);
        self.connections.insert(
            connection_id,
            Connection {
                socket,
                exposed: true,
                send_blocked: false,
                connecting: true,
                saw_eof: false,
                orphaned_at: None,
            },
        );
        Ok(connection_id)
    }

    fn receive(&mut self, packet: &[u8]) -> PyResult<()> {
        if packet.len() < 20 || packet[0] >> 4 != 4 {
            return Err(PacketError::new_err("packet must contain IPv4"));
        }
        if packet.len() > self.mtu {
            return Err(PacketError::new_err("packet exceeds the configured mtu"));
        }
        // With AnyIP smoltcp would answer pings for every address.
        if self.any_ip && packet[9] != u8::from(IpProtocol::Tcp) {
            return Err(PacketError::new_err("an any_ip stack only accepts TCP"));
        }
        self.device.received.push_back(packet.to_vec());
        Ok(())
    }

    /// Accepts a connection on behalf of the destination of a SYN.
    ///
    /// The stack listens on exactly that destination address and port, then
    /// processes the SYN at once, so the connection is bound to its peer before
    /// any other packet can reach the listening socket. The caller decides when
    /// to intercept: holding the SYN until the real destination answers keeps a
    /// refused destination from looking connected.
    fn intercept(&mut self, packet: &[u8], buffer_size: usize, timestamp_us: i64) -> PyResult<u64> {
        if !self.any_ip {
            return Err(PacketError::new_err("intercept requires an any_ip stack"));
        }
        if buffer_size == 0 {
            return Err(PyValueError::new_err(
                "buffer_size must be greater than zero",
            ));
        }
        if packet.len() > self.mtu {
            return Err(PacketError::new_err("packet exceeds the configured mtu"));
        }
        let ip = Ipv4Packet::new_checked(packet)
            .map_err(|_| PacketError::new_err("packet must contain IPv4"))?;
        if ip.next_header() != IpProtocol::Tcp {
            return Err(PacketError::new_err("packet must contain TCP"));
        }
        let tcp = TcpPacket::new_checked(ip.payload())
            .map_err(|_| PacketError::new_err("packet must contain TCP"))?;
        if !tcp.syn() || tcp.ack() || tcp.rst() {
            return Err(PacketError::new_err(
                "only a SYN starts an intercepted connection",
            ));
        }
        let (source, destination) = (ip.src_addr(), ip.dst_addr());
        let (source_port, destination_port) = (tcp.src_port(), tcp.dst_port());
        let unicast = !(destination.is_multicast()
            || destination.is_broadcast()
            || destination.is_unspecified());
        if destination_port == 0 || !unicast {
            return Err(PacketError::new_err("the destination is not addressable"));
        }
        let duplicate = self.connections.values().any(|connection| {
            let socket = self.sockets.get::<tcp::Socket>(connection.socket);
            socket.local_endpoint().is_some_and(|local| {
                local.addr == IpAddress::Ipv4(destination) && local.port == destination_port
            }) && socket.remote_endpoint().is_some_and(|remote| {
                remote.addr == IpAddress::Ipv4(source) && remote.port == source_port
            })
        });
        if duplicate {
            return Err(AddressInUseError::new_err(
                "the connection is already intercepted",
            ));
        }

        let mut socket = tcp_socket(buffer_size);
        socket.set_congestion_control(tcp::CongestionControl::Cubic);
        let endpoint = IpListenEndpoint {
            addr: Some(IpAddress::Ipv4(destination)),
            port: destination_port,
        };
        socket
            .listen(endpoint)
            .map_err(|error| PyValueError::new_err(format!("listen failed: {error}")))?;
        let handle = self.sockets.add(socket);
        let connection_id = self.next_connection;
        self.next_connection += 1;
        self.connections.insert(
            connection_id,
            Connection {
                socket: handle,
                exposed: true,
                send_blocked: false,
                connecting: true,
                saw_eof: false,
                orphaned_at: None,
            },
        );
        self.device.received.push_back(packet.to_vec());
        self.advance(timestamp_us)?;
        Ok(connection_id)
    }

    fn advance(&mut self, timestamp_us: i64) -> PyResult<()> {
        self.now = self.now.max(timestamp_us);
        self.expire_orphans();
        self.poll();
        self.reap_orphans();
        self.collect_connections()?;
        Ok(())
    }

    fn transmit<'py>(&mut self, python: Python<'py>) -> Vec<Bound<'py, PyBytes>> {
        self.device
            .transmitted
            .drain(..)
            .map(|packet| PyBytes::new(python, &packet))
            .collect()
    }

    fn next_delay(&mut self, timestamp_us: i64) -> Option<i64> {
        self.now = self.now.max(timestamp_us);
        if !self.detached.is_empty() {
            return Some(0);
        }
        let timestamp = Instant::from_micros(self.now);
        let network = self
            .interface
            .poll_delay(timestamp, &self.sockets)
            .map(|delay| delay.total_micros() as i64);
        let orphans = self
            .connections
            .values()
            .filter_map(|connection| connection.orphaned_at)
            .map(|orphaned_at| (orphaned_at + ORPHAN_TIMEOUT_US - self.now).max(0))
            .min();
        match (network, orphans) {
            (Some(network), Some(orphans)) => Some(network.min(orphans)),
            (network, orphans) => network.or(orphans),
        }
    }

    #[pyo3(signature = (connection_id, maximum=None))]
    fn connection_receive<'py>(
        &mut self,
        python: Python<'py>,
        connection_id: u64,
        maximum: Option<usize>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let handle = self.connection_handle(connection_id)?;
        let socket = self.sockets.get_mut::<tcp::Socket>(handle);
        let length = maximum
            .unwrap_or(socket.recv_queue())
            .min(socket.recv_queue());
        if length == 0 {
            return Ok(PyBytes::new(python, &[]));
        }
        PyBytes::new_with(python, length, |buffer| {
            socket
                .recv_slice(buffer)
                .map(|_| ())
                .map_err(|error| TCPStateError::new_err(format!("receive failed: {error}")))
        })
    }

    fn connection_send(&mut self, connection_id: u64, content: &[u8]) -> PyResult<usize> {
        let handle = self.connection_handle(connection_id)?;
        let sent = self
            .sockets
            .get_mut::<tcp::Socket>(handle)
            .send_slice(content)
            .map_err(|error| TCPStateError::new_err(format!("send failed: {error}")))?;
        self.connections
            .get_mut(&connection_id)
            .expect("the connection handle was already resolved")
            .send_blocked = sent < content.len();
        Ok(sent)
    }

    fn connection_close(&mut self, connection_id: u64) -> PyResult<()> {
        let handle = self.connection_handle(connection_id)?;
        self.sockets.get_mut::<tcp::Socket>(handle).close();
        Ok(())
    }

    fn connection_abort(&mut self, connection_id: u64) -> PyResult<()> {
        let handle = self.connection_handle(connection_id)?;
        self.sockets.get_mut::<tcp::Socket>(handle).abort();
        Ok(())
    }

    /// Releases a connection that Python no longer references.
    ///
    /// A connection that is already closing (`close()` was called) keeps running
    /// detached from Python until the FIN handshake completes or the orphan
    /// timeout expires, so queued data is still delivered. Any other connection
    /// is aborted and the reset goes out on the next poll.
    fn connection_release(&mut self, connection_id: u64) -> PyResult<()> {
        let handle = self.connection_handle(connection_id)?;
        let closing = matches!(
            self.sockets.get::<tcp::Socket>(handle).state(),
            tcp::State::FinWait1
                | tcp::State::FinWait2
                | tcp::State::Closing
                | tcp::State::LastAck
                | tcp::State::TimeWait
        );
        if closing {
            let connection = self
                .connections
                .get_mut(&connection_id)
                .expect("the connection handle was already resolved");
            connection.exposed = false;
            connection.orphaned_at = Some(self.now);
        } else {
            self.connections.remove(&connection_id);
            self.detach(handle);
        }
        Ok(())
    }

    /// Aborts every socket, transmits the resulting resets and frees all state.
    fn shutdown(&mut self) {
        let listeners = std::mem::take(&mut self.listeners);
        for listener in listeners.into_values() {
            for socket in listener.pending {
                self.detach(socket);
            }
        }
        let connections = std::mem::take(&mut self.connections);
        for connection in connections.into_values() {
            self.detach(connection.socket);
        }
        self.poll();
    }

    fn connection_state(&self, connection_id: u64) -> PyResult<&'static str> {
        let handle = self.connection_handle(connection_id)?;
        let socket = self.sockets.get::<tcp::Socket>(handle);
        Ok(state_name(socket.state()))
    }

    fn connection_endpoints(&self, connection_id: u64) -> PyResult<(Endpoint, Endpoint)> {
        let handle = self.connection_handle(connection_id)?;
        let socket = self.sockets.get::<tcp::Socket>(handle);
        let local = socket
            .local_endpoint()
            .map(|endpoint| (endpoint.addr.to_string(), endpoint.port));
        let remote = socket
            .remote_endpoint()
            .map(|endpoint| (endpoint.addr.to_string(), endpoint.port));
        Ok((local, remote))
    }

    fn connection_can_receive(&self, connection_id: u64) -> PyResult<bool> {
        let handle = self.connection_handle(connection_id)?;
        Ok(self.sockets.get::<tcp::Socket>(handle).can_recv())
    }

    fn connection_can_send(&self, connection_id: u64) -> PyResult<bool> {
        let handle = self.connection_handle(connection_id)?;
        Ok(self.sockets.get::<tcp::Socket>(handle).can_send())
    }

    fn connection_eof(&self, connection_id: u64) -> PyResult<bool> {
        let handle = self.connection_handle(connection_id)?;
        Ok(socket_eof(self.sockets.get::<tcp::Socket>(handle)))
    }

    /// Reports `readable` while data is buffered. `writable` is reported once
    /// when an outgoing connection is established or when a short `send()` can
    /// continue; `eof` is reported once when the peer finishes or resets.
    fn connection_events(&mut self) -> Vec<(u64, bool, bool, bool)> {
        let mut events = vec![];
        for (connection_id, connection) in &mut self.connections {
            if !connection.exposed {
                continue;
            }
            let socket = self.sockets.get::<tcp::Socket>(connection.socket);
            let readable = socket.can_recv();

            // Outgoing connects start in SYN-SENT; intercepted ones in SYN-RECEIVED.
            let connected = connection.connecting
                && !matches!(
                    socket.state(),
                    tcp::State::Listen | tcp::State::SynSent | tcp::State::SynReceived
                );
            if connected {
                connection.connecting = false;
            }
            let writable = (connected || connection.send_blocked) && socket.can_send();
            if writable {
                connection.send_blocked = false;
            }

            let eof = !connection.saw_eof && socket_eof(socket);
            if eof {
                connection.saw_eof = true;
            }
            if readable || writable || eof {
                events.push((*connection_id, readable, writable, eof));
            }
        }
        events
    }

    fn connection_count(&self) -> usize {
        self.connections.len()
    }
}

impl Engine {
    fn ephemeral_port(&mut self) -> PyResult<u16> {
        let start = self.ports.next_u32() % EPHEMERAL_PORTS;
        let stride = (self.ports.next_u32() | 1) % EPHEMERAL_PORTS;
        for index in 0..EPHEMERAL_PORTS {
            let offset = (start + index * stride) % EPHEMERAL_PORTS;
            let port = 49152 + offset as u16;
            if !self.port_in_use(port) {
                return Ok(port);
            }
        }
        Err(AddressInUseError::new_err(
            "no ephemeral TCP ports are available",
        ))
    }

    fn port_in_use(&self, port: u16) -> bool {
        // Intercepted connections use foreign addresses and never take a local port.
        let own = IpAddress::Ipv4(self.address);
        self.listeners
            .values()
            .any(|listener| listener.port == port)
            || self.connections.values().any(|connection| {
                self.sockets
                    .get::<tcp::Socket>(connection.socket)
                    .local_endpoint()
                    .is_some_and(|endpoint| endpoint.port == port && endpoint.addr == own)
            })
    }

    fn connection_handle(&self, connection_id: u64) -> PyResult<SocketHandle> {
        self.connections
            .get(&connection_id)
            .filter(|connection| connection.orphaned_at.is_none())
            .map(|connection| connection.socket)
            .ok_or_else(|| PyKeyError::new_err("unknown connection"))
    }

    fn fill_listener(&mut self, listener_id: u64) -> PyResult<()> {
        loop {
            let (port, buffer_size, missing) = {
                let listener = self
                    .listeners
                    .get(&listener_id)
                    .ok_or_else(|| PyKeyError::new_err("unknown listener"))?;
                (
                    listener.port,
                    listener.buffer_size,
                    listener
                        .backlog
                        .saturating_sub(listener.pending.len() + listener.accepted.len()),
                )
            };
            if missing == 0 {
                return Ok(());
            }

            let mut socket = tcp_socket(buffer_size);
            socket.set_congestion_control(tcp::CongestionControl::Cubic);
            // Bound to the stack's own address: with AnyIP a bare port would also
            // catch connections meant for intercepted destinations.
            let endpoint = IpListenEndpoint {
                addr: Some(IpAddress::Ipv4(self.address)),
                port,
            };
            socket
                .listen(endpoint)
                .map_err(|error| PyValueError::new_err(format!("listen failed: {error}")))?;
            let handle = self.sockets.add(socket);
            self.listeners
                .get_mut(&listener_id)
                .expect("listener exists while it is being filled")
                .pending
                .push(handle);
        }
    }

    fn collect_connections(&mut self) -> PyResult<()> {
        let listener_ids: Vec<u64> = self.listeners.keys().copied().collect();
        for listener_id in listener_ids {
            let pending = self
                .listeners
                .get(&listener_id)
                .expect("listener id came from the listener table")
                .pending
                .clone();
            let mut established = vec![];
            let mut closed = vec![];

            for handle in pending {
                let state = self.sockets.get::<tcp::Socket>(handle).state();
                match state {
                    tcp::State::Listen | tcp::State::SynReceived => {}
                    tcp::State::Closed => closed.push(handle),
                    _ => established.push(handle),
                }
            }

            for handle in closed {
                self.remove_pending(listener_id, handle);
                self.sockets.remove(handle);
            }
            for handle in established {
                self.remove_pending(listener_id, handle);
                let connection_id = self.next_connection;
                self.next_connection += 1;
                self.connections.insert(
                    connection_id,
                    Connection {
                        socket: handle,
                        exposed: false,
                        send_blocked: false,
                        connecting: false,
                        saw_eof: false,
                        orphaned_at: None,
                    },
                );
                self.listeners
                    .get_mut(&listener_id)
                    .expect("listener exists while accepting connections")
                    .accepted
                    .push_back(connection_id);
            }
            self.fill_listener(listener_id)?;
        }
        Ok(())
    }

    fn poll(&mut self) {
        let timestamp = Instant::from_micros(self.now);
        self.interface
            .poll(timestamp, &mut self.device, &mut self.sockets);
        // Every detached socket was aborted before this poll, which has now
        // emitted its reset, so the socket can be freed.
        for handle in std::mem::take(&mut self.detached) {
            self.sockets.remove(handle);
        }
    }

    /// Aborts a socket and frees it after the next poll transmits the reset.
    fn detach(&mut self, handle: SocketHandle) {
        self.sockets.get_mut::<tcp::Socket>(handle).abort();
        self.detached.push(handle);
    }

    fn expire_orphans(&mut self) {
        let expired: Vec<u64> = self
            .connections
            .iter()
            .filter(|(_, connection)| {
                connection
                    .orphaned_at
                    .is_some_and(|orphaned_at| self.now - orphaned_at >= ORPHAN_TIMEOUT_US)
            })
            .map(|(connection_id, _)| *connection_id)
            .collect();
        for connection_id in expired {
            let connection = self
                .connections
                .remove(&connection_id)
                .expect("expired orphans come from the connection table");
            self.detach(connection.socket);
        }
    }

    fn reap_orphans(&mut self) {
        let closed: Vec<u64> = self
            .connections
            .iter()
            .filter(|(_, connection)| {
                connection.orphaned_at.is_some()
                    && self.sockets.get::<tcp::Socket>(connection.socket).state()
                        == tcp::State::Closed
            })
            .map(|(connection_id, _)| *connection_id)
            .collect();
        for connection_id in closed {
            let connection = self
                .connections
                .remove(&connection_id)
                .expect("closed orphans come from the connection table");
            self.sockets.remove(connection.socket);
        }
    }

    fn remove_pending(&mut self, listener_id: u64, handle: SocketHandle) {
        let listener = self
            .listeners
            .get_mut(&listener_id)
            .expect("listener exists while removing a pending socket");
        listener.pending.retain(|pending| *pending != handle);
    }
}

fn tcp_socket(buffer_size: usize) -> tcp::Socket<'static> {
    let receive = tcp::SocketBuffer::new(vec![0; buffer_size]);
    let transmit = tcp::SocketBuffer::new(vec![0; buffer_size]);
    let mut socket = tcp::Socket::new(receive, transmit);
    socket.set_ack_delay(None);
    socket
}

fn parse_address(ip_address: &str) -> PyResult<Ipv4Addr> {
    Ipv4Addr::from_str(ip_address)
        .map_err(|_| PyValueError::new_err(format!("invalid IPv4 address: {ip_address}")))
}

fn socket_eof(socket: &tcp::Socket<'_>) -> bool {
    !socket.may_recv()
        && !matches!(
            socket.state(),
            tcp::State::Listen | tcp::State::SynSent | tcp::State::SynReceived
        )
}

fn state_name(state: tcp::State) -> &'static str {
    match state {
        tcp::State::Closed => "CLOSED",
        tcp::State::Listen => "LISTEN",
        tcp::State::SynSent => "SYN_SENT",
        tcp::State::SynReceived => "SYN_RECEIVED",
        tcp::State::Established => "ESTABLISHED",
        tcp::State::FinWait1 => "FIN_WAIT_1",
        tcp::State::FinWait2 => "FIN_WAIT_2",
        tcp::State::CloseWait => "CLOSE_WAIT",
        tcp::State::Closing => "CLOSING",
        tcp::State::LastAck => "LAST_ACK",
        tcp::State::TimeWait => "TIME_WAIT",
    }
}
