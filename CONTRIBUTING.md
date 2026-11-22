# Contributing

Thank you for helping improve `tcp-sansio`. Bug reports, questions and pull
requests are welcome.

## Development setup

You need Python 3.10 or newer and a recent stable
[Rust toolchain](https://rustup.rs/).

```
python -m venv .venv
# Windows: .venv\Scripts\activate    Linux and macOS: source .venv/bin/activate
python -m pip install maturin pytest
maturin develop --release
python -m pytest
```

Run `maturin develop` again after changing Rust code. Python changes under
`python/tcp_sansio` are picked up without rebuilding.

## Project layout

- `src/`: the native extension, which wraps `smoltcp` with PyO3.
- `python/tcp_sansio/`: the public Python API and its type stubs.
- `tests/`: the test suite, which runs entirely in memory.
- `examples/`: small programs that are also run by CI.

## Before opening a pull request

- Add or update tests for the behaviour you change.
- Run `cargo fmt`, `cargo clippy --all-targets -- -D warnings` and
  `python -m pytest`. CI runs the same checks on Linux, Windows and macOS.
- Describe user-visible changes under `[Unreleased]` in `CHANGELOG.md`.

## Releases

Maintainers bump the version in `Cargo.toml`, move the changelog entries to a
new version section and publish a GitHub release tagged `vX.Y.Z`. The release
workflow builds the wheels and the source distribution and uploads them to
PyPI.

## License

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in this project by you, as defined in the Apache-2.0
license, shall be dual licensed under the MIT and Apache-2.0 licenses, without
any additional terms or conditions.
