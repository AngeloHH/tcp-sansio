import gc

import pytest

from tcp_sansio import AddressInUseError, PacketError, TCPStack


class Clock:
    def __init__(self): self.value = 0

    def __call__(self):
        self.value += .001
        return self.value


def exchange(left, right, milliseconds=1):
    for _ in range(milliseconds):
        for packet in left.transmit(): right.receive(packet)
        for packet in right.transmit(): left.receive(packet)


def connection_pair(buffer_size=65535):
    clock = Clock()
    client = TCPStack("10.0.0.2", seed=1, clock=clock)
    server = TCPStack("10.0.0.1", seed=2, clock=clock)
    listener = server.listen(8080, buffer_size=buffer_size)
    connection = client.connect("10.0.0.1", 8080, 50000, buffer_size)

    for _ in range(1000):
        for packet in client.transmit(): server.receive(packet)
        for packet in server.transmit(): client.receive(packet)
        accepted = listener.accept()
        if accepted is not None: return client, server, connection, accepted

    raise AssertionError("connection did not become established")


def test_bidirectional_transfer():
    client, server, outgoing, incoming = connection_pair()

    assert outgoing.state == "ESTABLISHED"
    assert incoming.state == "ESTABLISHED"
    assert not outgoing.eof and not incoming.eof
    assert outgoing.send(b"request") == 7
    exchange(client, server, 20)
    assert incoming.receive() == b"request"

    assert incoming.send(b"response") == 8
    exchange(server, client, 20)
    assert outgoing.receive() == b"response"


def test_listener_accepts_backlog_connections():
    server = TCPStack("10.0.0.1", seed=1)
    first = TCPStack("10.0.0.2", seed=2)
    second = TCPStack("10.0.0.3", seed=3)
    listener = server.listen(80, backlog=2)
    outgoing = [first.connect("10.0.0.1", 80, 50001),
                second.connect("10.0.0.1", 80, 50002)]

    accepted = []
    for tick in range(1000):
        timestamp = tick / 1000
        for packet in first.transmit(timestamp): server.receive(packet, timestamp)
        for packet in second.transmit(timestamp): server.receive(packet, timestamp)
        for packet in server.transmit(timestamp):
            destination = packet[16:20]
            if destination == bytes((10, 0, 0, 2)): first.receive(packet, timestamp)
            if destination == bytes((10, 0, 0, 3)): second.receive(packet, timestamp)
        while connection := listener.accept(): accepted.append(connection)
        if len(accepted) == 2: break

    assert len(accepted) == 2


def test_retransmits_after_packet_loss():
    client = TCPStack("10.0.0.2", seed=1)
    server = TCPStack("10.0.0.1", seed=2)
    listener = server.listen(443)
    outgoing = client.connect("10.0.0.1", 443, 50000)
    client.transmit(0)  # Drop the first SYN.

    incoming = None
    for tick in range(1, 5000):
        timestamp = tick / 1000
        for packet in client.transmit(timestamp): server.receive(packet, timestamp)
        for packet in server.transmit(timestamp): client.receive(packet, timestamp)
        incoming = listener.accept()
        if incoming is not None: break

    assert incoming is not None
    assert outgoing.state == "ESTABLISHED"


def test_assigns_ephemeral_port_and_reports_endpoints():
    client = TCPStack("10.0.0.2", seed=1)
    connection = client.connect("10.0.0.1", 443)

    assert 49152 <= connection.local_address[1] <= 65535
    assert connection.remote_address == ("10.0.0.1", 443)


def test_rejects_time_moving_backwards():
    stack = TCPStack("10.0.0.1", seed=1)
    stack.advance(2)

    try: stack.advance(1)
    except ValueError as error: assert str(error) == "timestamp cannot move backwards"
    else: raise AssertionError("a decreasing timestamp was accepted")


def test_rejects_mixing_automatic_and_manual_time():
    stack = TCPStack("10.0.0.1", seed=1, clock=Clock())
    stack.advance()

    with pytest.raises(ValueError, match="cannot be mixed"):
        stack.advance(2)


def test_stacks_allow_overlapping_addresses():
    first = connection_pair()
    second = connection_pair()

    assert first[0].ip_address == second[0].ip_address
    assert first[1].ip_address == second[1].ip_address
    assert first[2].state == second[2].state == "ESTABLISHED"


def test_recovers_stream_when_ip_packets_arrive_reordered():
    client = TCPStack("10.0.0.2", seed=1)
    server = TCPStack("10.0.0.1", seed=2)
    listener = server.listen(8080)
    outgoing = client.connect("10.0.0.1", 8080, 50000)

    incoming = None
    for tick in range(1000):
        timestamp = tick / 1000
        for packet in client.transmit(timestamp): server.receive(packet, timestamp)
        for packet in server.transmit(timestamp): client.receive(packet, timestamp)
        incoming = listener.accept()
        if incoming is not None: break
    assert incoming is not None

    for _ in range(3):
        tick += 1
        timestamp = tick / 1000
        outgoing.send(b'x' * 1400)
        for packet in client.transmit(timestamp): server.receive(packet, timestamp)
        for packet in server.transmit(timestamp): client.receive(packet, timestamp)
        assert incoming.receive() == b'x' * 1400

    content = bytes(range(256)) * 20
    assert outgoing.send(content) == len(content)

    tick += 1
    timestamp = tick / 1000
    packets = client.transmit(timestamp)
    assert len(packets) >= 3
    for packet in reversed(packets): server.receive(packet, timestamp)
    for packet in server.transmit(timestamp): client.receive(packet, timestamp)

    received = incoming.receive()
    for _ in range(5):
        tick += 1000
        timestamp = tick / 1000
        for packet in client.transmit(timestamp): server.receive(packet, timestamp)
        for packet in server.transmit(timestamp): client.receive(packet, timestamp)
        received += incoming.receive()
        if received == content: break

    assert received == content


def test_backlog_counts_connections_waiting_for_accept():
    server = TCPStack("10.0.0.1", seed=1, clock=None)
    listener = server.listen(80, backlog=1, buffer_size=64)
    clients = [TCPStack(f"10.0.0.{index}", seed=index, clock=None)
               for index in range(2, 12)]
    outgoing = [client.connect("10.0.0.1", 80, index, 64)
                for index, client in enumerate(clients, 50000)]

    for tick in range(100):
        timestamp = tick / 1000
        for client in clients:
            for packet in client.transmit(timestamp): server.receive(packet, timestamp)
        for packet in server.transmit(timestamp):
            destination = packet[16:20]
            for client in clients:
                address = bytes(map(int, client.ip_address.split('.')))
                if destination == address: client.receive(packet, timestamp)

    assert server._engine.connection_count() == 1
    assert listener.accept() is not None


def test_closing_listener_releases_unaccepted_connections():
    client = TCPStack("10.0.0.2", seed=1, clock=None)
    server = TCPStack("10.0.0.1", seed=2, clock=None)
    listener = server.listen(80)
    outgoing = client.connect("10.0.0.1", 80, 50000)

    for tick in range(100):
        timestamp = tick / 1000
        for packet in client.transmit(timestamp): server.receive(packet, timestamp)
        for packet in server.transmit(timestamp): client.receive(packet, timestamp)
        if server._engine.connection_count(): break

    assert server._engine.connection_count() == 1
    listener.close()
    assert server._engine.connection_count() == 0


def test_events_report_readable_writable_and_eof():
    client, server, outgoing, incoming = connection_pair(buffer_size=8)
    assert outgoing.send(b"123456789") == 8
    assert client.events() == []
    exchange(client, server, 20)

    server_event = server.events()[0]
    client_event = client.events()[0]
    assert server_event.connection is incoming and server_event.readable
    assert client_event.connection is outgoing and client_event.writable
    assert incoming.receive() == b"12345678"

    outgoing.close()
    exchange(client, server, 20)
    assert incoming.eof
    assert any(event.connection is incoming and event.eof
               for event in server.events())


def test_release_and_garbage_collection_free_connections():
    stack = TCPStack("10.0.0.1", seed=1)
    first = stack.connect("10.0.0.2", 80)
    assert stack._engine.connection_count() == 1
    first.release()
    assert first.released and stack._engine.connection_count() == 0

    second = stack.connect("10.0.0.2", 80)
    assert stack._engine.connection_count() == 1
    del second
    gc.collect()
    assert stack._engine.connection_count() == 0


def test_releasing_active_connection_transmits_reset():
    client, server, outgoing, incoming = connection_pair()
    outgoing.release()
    for packet in client.transmit(): server.receive(packet)

    assert incoming.state == "CLOSED"
    assert incoming.eof


def test_closing_stack_marks_live_resources_released():
    stack = TCPStack("10.0.0.1", seed=1)
    listener = stack.listen(80)
    connection = stack.connect("10.0.0.2", 80)
    stack.close()

    assert listener._closed
    assert connection.released
    assert stack._engine.connection_count() == 0


def test_rejects_ports_already_in_use():
    stack = TCPStack("10.0.0.1", seed=1)
    listener = stack.listen(50000)

    with pytest.raises(AddressInUseError):
        stack.connect("10.0.0.2", 80, 50000)


def test_validates_packets_and_mtu():
    with pytest.raises(ValueError, match="at least 40"):
        TCPStack("10.0.0.1", mtu=39)

    stack = TCPStack("10.0.0.1", mtu=40, seed=1)
    with pytest.raises(PacketError, match="must contain IPv4"):
        stack.receive(b"not an IP packet")
    with pytest.raises(PacketError, match="exceeds"):
        stack.receive(bytes((0x45,)) + bytes(40))


class Wire:
    """Two stacks joined by a lossless link, driven by explicit timestamps."""

    def __init__(self, client, server):
        self.client, self.server, self.now = client, server, 0.0

    def run(self, seconds=.02, step=.001):
        for _ in range(round(seconds / step)):
            self.now += step
            for packet in self.client.transmit(self.now): self.server.receive(packet, self.now)
            for packet in self.server.transmit(self.now): self.client.receive(packet, self.now)

    def jump(self, seconds):
        self.now += seconds
        self.run()


def manual_pair():
    client = TCPStack("10.0.0.2", seed=1, clock=None)
    server = TCPStack("10.0.0.1", seed=2, clock=None)
    wire = Wire(client, server)
    listener = server.listen(8080)
    outgoing = client.connect("10.0.0.1", 8080, 50000)
    wire.run()
    incoming = listener.accept()
    assert incoming is not None
    return wire, listener, outgoing, incoming


def test_releasing_after_close_delivers_queued_data():
    wire, listener, outgoing, incoming = manual_pair()
    content = bytes(range(256)) * 64
    assert outgoing.send(content) == len(content)
    outgoing.close()
    outgoing.release()
    assert wire.client._engine.connection_count() == 1

    received = b""
    for _ in range(50):
        wire.run()
        received += incoming.receive()
    assert received == content
    assert incoming.eof and incoming.state == "CLOSE_WAIT"

    incoming.close()
    wire.run()
    incoming.release()
    wire.jump(11)
    assert wire.client._engine.connection_count() == 0
    assert wire.server._engine.connection_count() == 0


def test_orphan_is_reset_after_timeout():
    wire, listener, outgoing, incoming = manual_pair()
    outgoing.close()
    outgoing.release()
    wire.run()
    assert incoming.state == "CLOSE_WAIT"

    deadline = wire.client.next_timeout(wire.now)
    assert deadline is not None and deadline <= 120
    wire.jump(120)
    assert wire.client._engine.connection_count() == 0
    assert incoming.state == "CLOSED"


def test_writable_reports_established_connect_once():
    wire, listener, outgoing, incoming = manual_pair()
    events = wire.client.events()
    assert [(event.connection, event.writable) for event in events] == [(outgoing, True)]
    assert wire.client.events() == []


def test_refused_connect_reports_eof_once():
    client = TCPStack("10.0.0.2", seed=1, clock=None)
    server = TCPStack("10.0.0.1", seed=2, clock=None)
    connection = client.connect("10.0.0.1", 9)
    Wire(client, server).run()

    events = client.events()
    assert [(event.connection, event.eof, event.writable) for event in events] == [
        (connection, True, False)]
    assert connection.state == "CLOSED"
    assert client.events() == []


def test_eof_is_reported_once():
    wire, listener, outgoing, incoming = manual_pair()
    wire.client.events()
    outgoing.close()
    wire.run()
    assert [event.eof for event in wire.server.events()] == [True]
    assert wire.server.events() == []
    assert incoming.eof


def test_closing_listener_resets_unaccepted_connections():
    client = TCPStack("10.0.0.2", seed=1, clock=None)
    server = TCPStack("10.0.0.1", seed=2, clock=None)
    wire = Wire(client, server)
    listener = server.listen(80)
    outgoing = client.connect("10.0.0.1", 80, 50000)
    wire.run()
    assert outgoing.state == "ESTABLISHED"

    listener.close()
    wire.run()
    assert outgoing.state == "CLOSED"


def test_closing_stack_returns_resets():
    wire, listener, outgoing, incoming = manual_pair()
    packets = wire.client.close()
    assert packets
    for packet in packets: wire.server.receive(packet, wire.now)
    assert incoming.state == "CLOSED"
    assert wire.client.close() == []


def test_events_are_ordered_by_connection():
    server = TCPStack("10.0.0.1", seed=1, clock=None)
    clients = [TCPStack(f"10.0.0.{index}", seed=index, clock=None)
               for index in range(2, 7)]
    listener = server.listen(80)
    outgoing = [client.connect("10.0.0.1", 80, 50000) for client in clients]

    accepted = []
    for tick in range(1, 50):
        timestamp = tick / 1000
        for client in clients:
            for packet in client.transmit(timestamp): server.receive(packet, timestamp)
        for packet in server.transmit(timestamp):
            for client in clients:
                if packet[16:20] == bytes(map(int, client.ip_address.split('.'))):
                    client.receive(packet, timestamp)
        while connection := listener.accept(): accepted.append(connection)
    assert len(accepted) == len(clients)

    for connection in outgoing: connection.send(b"x")
    for tick in range(50, 70):
        timestamp = tick / 1000
        for client in clients:
            for packet in client.transmit(timestamp): server.receive(packet, timestamp)
    ids = [event.connection.id for event in server.events()]
    assert len(ids) == len(clients) and ids == sorted(ids)


DESTINATION = "93.184.216.34"


def packet_route(packet):
    return ".".join(map(str, packet[12:16])), ".".join(map(str, packet[16:20]))


def intercepted_pair(client_address="10.0.0.5", seed=1, egress=None, clock=None):
    # The client believes it talks to DESTINATION; the egress stack answers for it.
    clock = clock or Clock()
    client = TCPStack(client_address, seed=seed, clock=clock)
    egress = egress or TCPStack("10.0.0.254", seed=99, clock=clock, any_ip=True)
    outgoing = client.connect(DESTINATION, 443, 50000)
    syn = client.transmit()
    assert len(syn) == 1
    incoming = egress.intercept(syn[0])
    exchange(client, egress, 20)
    return client, egress, outgoing, incoming


def test_intercept_answers_as_the_destination():
    client, egress, outgoing, incoming = intercepted_pair()

    assert outgoing.state == "ESTABLISHED" and incoming.state == "ESTABLISHED"
    assert incoming.local_address == (DESTINATION, 443)
    assert incoming.remote_address == ("10.0.0.5", 50000)
    assert outgoing.send(b"GET /") == 5
    for packet in client.transmit(): egress.receive(packet)
    assert incoming.receive() == b"GET /"
    incoming.send(b"200 OK")
    replies = egress.transmit()
    assert {packet_route(packet) for packet in replies} == {(DESTINATION, "10.0.0.5")}
    for packet in replies: client.receive(packet)
    assert outgoing.receive() == b"200 OK"


def test_intercepted_connection_reports_writable_once_established():
    clock = Clock()
    client = TCPStack("10.0.0.5", seed=1, clock=clock)
    egress = TCPStack("10.0.0.254", seed=99, clock=clock, any_ip=True)
    outgoing = client.connect(DESTINATION, 443, 50000)
    incoming = egress.intercept(client.transmit()[0])

    # The SYN-ACK is out but the handshake is not finished yet.
    assert incoming.state == "SYN_RECEIVED"
    assert egress.events() == []
    exchange(client, egress, 5)
    events = [event for event in egress.events() if event.connection is incoming]
    assert [(event.writable, event.eof) for event in events] == [(True, False)]
    assert outgoing.state == "ESTABLISHED"
    assert egress.events() == []


def test_several_peers_reach_the_same_destination():
    clock = Clock()
    egress = TCPStack("10.0.0.254", seed=99, clock=clock, any_ip=True)
    first = intercepted_pair("10.0.0.5", 1, egress, clock)
    second = intercepted_pair("10.0.0.6", 2, egress, clock)

    first[2].send(b"first"), second[2].send(b"second")
    for client in (first[0], second[0]):
        for packet in client.transmit(): egress.receive(packet)
    assert first[3].receive() == b"first" and second[3].receive() == b"second"
    assert egress.events() and egress._engine.connection_count() == 2


def test_a_syn_that_was_not_intercepted_is_refused():
    clock = Clock()
    client = TCPStack("10.0.0.5", seed=1, clock=clock)
    egress = TCPStack("10.0.0.254", seed=99, clock=clock, any_ip=True)
    outgoing = client.connect(DESTINATION, 443, 50000)

    for packet in client.transmit(): egress.receive(packet)
    resets = egress.transmit()
    assert [packet_route(packet) for packet in resets] == [(DESTINATION, "10.0.0.5")]
    for packet in resets: client.receive(packet)
    assert outgoing.state == "CLOSED" and outgoing.eof


def test_intercept_requires_an_any_ip_stack_and_a_new_syn():
    clock = Clock()
    client = TCPStack("10.0.0.5", seed=1, clock=clock)
    outgoing = client.connect(DESTINATION, 443, 50000)
    syn = client.transmit()[0]

    with pytest.raises(PacketError, match="any_ip"):
        TCPStack("10.0.0.254", seed=2, clock=clock).intercept(syn)
    egress = TCPStack("10.0.0.254", seed=99, clock=clock, any_ip=True)
    incoming = egress.intercept(syn)
    with pytest.raises(AddressInUseError):
        egress.intercept(syn)
    # A retransmitted SYN for an intercepted connection is ordinary traffic.
    egress.receive(syn)
    ack = egress.transmit()
    for packet in ack: client.receive(packet)
    final = client.transmit()[0]
    with pytest.raises(PacketError, match="SYN"):
        egress.intercept(final)
    egress.receive(final)
    with pytest.raises(PacketError):
        egress.intercept(b"\x45" + bytes(19))
    assert outgoing.state == "ESTABLISHED" and incoming.state == "ESTABLISHED"


def test_an_any_ip_stack_only_accepts_tcp():
    egress = TCPStack("10.0.0.254", seed=99, any_ip=True)
    header = bytearray(b"\x45\x00\x00\x1c" + bytes(4) + b"\x40\x01" + bytes(2))
    header += bytes((10, 0, 0, 5)) + bytes((1, 1, 1, 1))
    ping = bytes(header) + b"\x08\x00" + bytes(6)
    with pytest.raises(PacketError, match="TCP"):
        egress.receive(ping)
    with pytest.raises(PacketError, match="TCP"):
        egress.intercept(ping)
    # An ordinary stack keeps its previous behavior for other protocols.
    TCPStack("1.1.1.1", seed=1).receive(ping)


def test_a_listener_keeps_its_own_address_beside_intercepted_traffic():
    clock = Clock()
    egress = TCPStack("10.0.0.254", seed=99, clock=clock, any_ip=True)
    client, egress, _, intercepted = intercepted_pair(egress=egress, clock=clock)
    # The intercepted destination port does not occupy a port of the stack.
    listener = egress.listen(443)
    assert listener.accept() is None

    panel = client.connect("10.0.0.254", 443, 50001)
    exchange(client, egress, 20)
    accepted = listener.accept()
    assert accepted is not None and accepted.local_address == ("10.0.0.254", 443)
    assert panel.state == "ESTABLISHED" and intercepted.state == "ESTABLISHED"
