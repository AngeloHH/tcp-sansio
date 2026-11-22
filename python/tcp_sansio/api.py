import secrets
import time
from dataclasses import dataclass
from threading import RLock
from weakref import WeakValueDictionary, finalize

from ._native import Engine


def _microseconds(timestamp: float) -> int:
    return int(timestamp * 1000000)


class TCPConnection:
    def __init__(self, stack, connection_id: int):
        self._stack, self.id = stack, connection_id
        self._released = False
        self._finalizer = finalize(self, stack._release_connection, connection_id)

    @property
    def released(self) -> bool:
        return self._released

    @property
    def state(self) -> str:
        with self._stack._lock:
            return self._stack._engine.connection_state(self.id)

    @property
    def local_address(self):
        with self._stack._lock:
            return self._stack._engine.connection_endpoints(self.id)[0]

    @property
    def remote_address(self):
        with self._stack._lock:
            return self._stack._engine.connection_endpoints(self.id)[1]

    @property
    def can_receive(self) -> bool:
        with self._stack._lock:
            return self._stack._engine.connection_can_receive(self.id)

    @property
    def can_send(self) -> bool:
        with self._stack._lock:
            return self._stack._engine.connection_can_send(self.id)

    @property
    def eof(self) -> bool:
        with self._stack._lock:
            return self._stack._engine.connection_eof(self.id)

    def receive(self, maximum: int = None) -> bytes:
        with self._stack._lock:
            return self._stack._engine.connection_receive(self.id, maximum)

    def send(self, content: bytes) -> int:
        with self._stack._lock:
            return self._stack._engine.connection_send(self.id, content)

    def close(self):
        with self._stack._lock: self._stack._engine.connection_close(self.id)

    def abort(self):
        with self._stack._lock: self._stack._engine.connection_abort(self.id)

    def release(self):
        if self._released: return
        self._finalizer.detach()
        self._stack._release_connection(self.id)
        self._released = True

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.release()


@dataclass(frozen=True, slots=True)
class TCPEvent:
    connection: TCPConnection
    readable: bool
    writable: bool
    eof: bool


class TCPListener:
    def __init__(self, stack, listener_id: int, address: tuple[str, int]):
        self._stack, self.id = stack, listener_id
        self.address, self._closed = address, False
        self._finalizer = finalize(self, stack._close_listener, listener_id)

    def accept(self):
        if self._closed: raise RuntimeError('listener is closed')
        with self._stack._lock:
            connection_id = self._stack._engine.listener_accept(self.id)
            if connection_id is None: return None
            return self._stack._connection(connection_id)

    def close(self):
        if self._closed: return
        self._finalizer.detach()
        self._stack._close_listener(self.id)
        self._closed = True

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class TCPStack:
    def __init__(self, ip_address: str, mtu: int = 1500,
                 seed: int = None, clock=time.monotonic, any_ip: bool = False):
        # any_ip accepts packets for every destination; only intercept() answers them.
        if seed is None: seed = secrets.randbits(64)
        self.ip_address, self.mtu, self.any_ip = ip_address, mtu, any_ip
        self._engine = Engine(ip_address, mtu, seed, any_ip)
        self._connections = WeakValueDictionary()
        self._listeners = WeakValueDictionary()
        self._connection_ids, self._listener_ids = set(), set()
        self._timestamp, self._clock_mode = None, None
        self._clock, self._closed = clock, False
        self._lock = RLock()

    def _ensure_open(self):
        if self._closed: raise RuntimeError('TCP stack is closed')

    def _time(self, timestamp) -> int:
        mode = 'automatic' if timestamp is None else 'manual'
        if self._clock_mode is not None and mode != self._clock_mode:
            raise ValueError('automatic and explicit timestamps cannot be mixed')
        if timestamp is None:
            if self._clock is None: raise ValueError('an explicit timestamp is required')
            timestamp = self._clock()
        timestamp = _microseconds(timestamp)
        if timestamp < 0: raise ValueError('timestamp cannot be negative')
        if self._timestamp is not None and timestamp < self._timestamp:
            raise ValueError('timestamp cannot move backwards')
        self._timestamp, self._clock_mode = timestamp, mode
        return timestamp

    def _connection(self, connection_id: int) -> TCPConnection:
        connection = self._connections.get(connection_id)
        if connection: return connection
        connection = TCPConnection(self, connection_id)
        self._connections[connection_id] = connection
        self._connection_ids.add(connection_id)
        return connection

    def _release_connection(self, connection_id: int):
        with self._lock:
            try: self._engine.connection_release(connection_id)
            except KeyError: pass
            self._connections.pop(connection_id, None)
            self._connection_ids.discard(connection_id)

    def _close_listener(self, listener_id: int):
        with self._lock:
            try: self._engine.listener_close(listener_id)
            except KeyError: return
            self._listeners.pop(listener_id, None)
            self._listener_ids.discard(listener_id)

    def listen(self, port: int, backlog: int = 16,
               buffer_size: int = 65535) -> TCPListener:
        with self._lock:
            self._ensure_open()
            listener_id = self._engine.listen(port, backlog, buffer_size)
            listener = TCPListener(self, listener_id, (self.ip_address, port))
            self._listeners[listener_id] = listener
            self._listener_ids.add(listener_id)
            return listener

    def connect(self, ip_address: str, port: int, local_port: int = None,
                buffer_size: int = 65535) -> TCPConnection:
        with self._lock:
            self._ensure_open()
            arguments = ip_address, port, local_port, buffer_size
            return self._connection(self._engine.connect(*arguments))

    def intercept(self, packet: bytes, timestamp: float = None,
                  buffer_size: int = 65535) -> TCPConnection:
        # Answers a SYN as its destination; local_address is where the peer was going.
        with self._lock:
            self._ensure_open()
            timestamp = self._time(timestamp)
            return self._connection(self._engine.intercept(packet, buffer_size, timestamp))

    def receive(self, packet: bytes, timestamp: float = None):
        with self._lock:
            self._ensure_open()
            timestamp = self._time(timestamp)
            self._engine.receive(packet)
            self._engine.advance(timestamp)

    def advance(self, timestamp: float = None):
        with self._lock:
            self._ensure_open()
            self._engine.advance(self._time(timestamp))

    def transmit(self, timestamp: float = None) -> list[bytes]:
        with self._lock:
            self._ensure_open()
            self._engine.advance(self._time(timestamp))
            return self._engine.transmit()

    def next_timeout(self, timestamp: float = None):
        with self._lock:
            self._ensure_open()
            delay = self._engine.next_delay(self._time(timestamp))
        return None if delay is None else delay / 1000000

    def events(self) -> list[TCPEvent]:
        with self._lock:
            self._ensure_open()
            events = self._engine.connection_events()
            return [TCPEvent(self._connection(event[0]), *event[1:])
                    for event in events]

    def close(self) -> list[bytes]:
        with self._lock:
            if self._closed: return []
            for listener in tuple(self._listeners.values()):
                listener._finalizer.detach()
                listener._closed = True
            for connection in tuple(self._connections.values()):
                connection._finalizer.detach()
                connection._released = True
            self._listeners.clear(), self._connections.clear()
            self._listener_ids.clear(), self._connection_ids.clear()
            self._engine.shutdown()
            self._closed = True
            return self._engine.transmit()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
