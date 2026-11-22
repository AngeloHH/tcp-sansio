# Changelog

All notable changes to this project are documented in this file. The format
is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the
project follows [Semantic Versioning](https://semver.org/). While the version
is `0.x`, minor releases may change the public API.

## [Unreleased]

## [0.1.0] - 2026-11-22

First public release.

### Added

- `TCPStack`, a Sans-I/O IPv4 TCP stack backed by `smoltcp`: applications feed
  raw packets with `receive()`, collect outgoing packets with `transmit()` and
  drive timers with `advance()` and `next_timeout()`.
- Outgoing connections with `connect()`, including randomized ephemeral ports,
  and listeners with `listen()` and `accept()` whose backlog bounds pending
  and unaccepted connections.
- `events()`, reporting readable data, writable space, completed connections
  and end of stream for every connection.
- Orderly release: a connection released after `close()` finishes its FIN
  handshake in the background; other released connections are reset.
- `any_ip` stacks and `intercept()`, which answer a client's SYN as the
  destination it was addressed to, for VPN and proxy servers.
- Automatic or explicit timestamps, and seeded randomness for reproducible
  simulations.
- `AddressInUseError`, `PacketError` and `TCPStateError` exceptions.
- Type hints for the whole public API.

[Unreleased]: https://github.com/AngeloHH/tcp-sansio/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/AngeloHH/tcp-sansio/releases/tag/v0.1.0
