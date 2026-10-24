# zklaim

[![CI](https://github.com/kiliant/zklaim/actions/workflows/ci.yml/badge.svg)](https://github.com/kiliant/zklaim/actions/workflows/ci.yml)

zklaim is a C library for zero-knowledge credentials. An issuer signs commitments to a holder's numeric attributes. The holder then proves predicates over those attributes, such as "born before 2008" or "country code equals 276", to verifiers without revealing the values. Proofs are Groth16 zk-SNARKs over SHA-256 commitments, built with libsnark; issuer signatures are Ed25519.

## Quick start

Install a C/C++ compiler, CMake 3.13 or newer, pkg-config, GMP, libgcrypt, and OpenSSL 1.1.1 or newer ([per-platform commands](docs/building.md#requirements)). Then:

```sh
git clone https://github.com/kiliant/zklaim.git
cd zklaim
git submodule update --init --recursive
cmake -S . -B build        # macOS: add -DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3)
cmake --build build --parallel
build/zklaim/main                        # example: issuer, prover, verifier
cmake --build build --target bttest      # unit tests
```

## Documentation

The [documentation](docs/README.md) covers:

- [Concepts](docs/concepts.md): roles, credentials, predicates, trusted setup, and the protocol flow
- [Building](docs/building.md): requirements, build options, installing and linking, containers
- [Developer guide](docs/guide.md): issuing, proving, and verifying with code
- [API reference](docs/api.md): all public types and functions
- [Security](docs/security.md): guarantees, trust assumptions, verifier checklist, limitations
- [Design](docs/design.md): the circuit, public input layout, and measured cost
- [Wire format](docs/wire-format.md): byte-level specification and migration from version 1
- [Development](docs/development.md): repository layout, tests, CI, benchmarks

## License

zklaim is free software under the GNU Lesser General Public License, version 3 or (at your option) any later version. [LICENSE](LICENSE) contains the LGPL, which supplements the GNU General Public License in [COPYING](COPYING).

The libsnark and libff submodules are MIT licensed. libff is linked statically into `libzklaim`, so binary distributions must include its license notice.
