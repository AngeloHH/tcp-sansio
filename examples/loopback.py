"""Two TCP stacks talking through an in-memory link.

Every packet one stack transmits is handed to the other one, so the whole TCP
conversation (handshake, data, acknowledgements and shutdown) happens inside
this process, without sockets, threads or network adapters.
"""

from tcp_sansio import TCPStack

# clock=None makes both stacks use the timestamps passed below, so the run is
# deterministic and does not depend on how fast the machine is.
client = TCPStack("10.0.0.2", clock=None)
server = TCPStack("10.0.0.1", clock=None)
now = 0.0


def run(milliseconds: int = 10):
    """Moves time forward and carries packets in both directions."""
    global now
    for _ in range(milliseconds):
        now += 0.001
        for packet in client.transmit(now): server.receive(packet, now)
        for packet in server.transmit(now): client.receive(packet, now)


listener = server.listen(7)
outgoing = client.connect("10.0.0.1", 7)
run()
incoming = listener.accept()
print("connected:", outgoing.local_address, "->", outgoing.remote_address)

# The server echoes what it receives.
outgoing.send(b"hello over a userspace TCP stack")
run()
request = incoming.receive()
incoming.send(request.upper())
run()
print("client received:", outgoing.receive())

# Orderly shutdown from both sides.
outgoing.close()
run()
assert incoming.eof
incoming.close()
run()
print("states:", outgoing.state, "/", incoming.state)
