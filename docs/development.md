# Development

## Repository layout

| Path | Contents |
| --- | --- |
| `zklaim/zklaim.h`, `zklaim/zklaim.c` | Contexts, signing, verification, serialization |
| `zklaim/zklaim_ecc.*` | Ed25519 keys and signatures |
| `zklaim/zklaim_hash.*` | SHA-256 helpers |
| `zklaim/zklaim_wire.h` | Wire format constants and encoders |
| `zklaim/zklaim_export.h` | `ZKLAIM_API` visibility macro |
| `zklaim/libsnark_wrapper.cpp` | C interface to libsnark: setup, proving, verification, key and proof encoding |
| `zklaim/snark.hpp` | Key generation, proving, and verification on top of the gadget |
| `zklaim/zklaim_gadget.hpp` | The circuit, described in [Design](design.md#circuit) |
| `zklaim/main.c`, `zklaim/main_benchmark.c` | Example and benchmark |
| `zklaim/tests/` | Unit tests, test keys, and the wire portability tool |
| `lib/` | libsnark and googletest submodules and their build glue |
| `docs/` | This documentation |

## Tests

The unit tests use googletest. Build and run all of them with:

```sh
cmake --build build --target bttest
```

The target copies `zklaim/tests` into the build directory, which holds the test keys, and runs `bttestc`. Afterwards, run a subset from `build/zklaim` with a googletest filter:

```sh
cd build/zklaim
./bttestc --gtest_filter='zklaim_verifier.*'
```

| Suite | Covers |
| --- | --- |
| `zklaim` | Contexts, attributes, setup, signing, proving, the circuit, and a full three-party run |
| `zklaim_ecc` | Ed25519 keys and signatures, RFC 8032 vectors, and interoperability with OpenSSL |
| `zklaim_deserialize` | Wire format round trips, a golden frame, truncation, corruption, and overflow handling |
| `zklaim_snark_parsing` | Rejection of malformed keys and proofs |
| `zklaim_verifier` | Trusted issuers, policy matching, nonces, and verification key pinning |

Configure with `-DCMAKE_CXX_FLAGS_RELWITHDEBINFO="-O2 -g -DDEBUG"`, as CI does, to enable libsnark's assertions and witness diagnostics.

## Wire portability

`wire_portability` issues a presentation from fixed public test keys and verifies one:

```sh
build/zklaim/wire_portability issue /tmp/presentation.zkp /tmp/presentation.vk
build/zklaim/wire_portability verify /tmp/presentation.zkp /tmp/presentation.vk
```

Verification also re-serializes the presentation and requires identical bytes. CI uses it to exchange presentations between platforms.

## Continuous integration

GitHub Actions runs [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) for every push to `master` and every pull request:

| Job | Does |
| --- | --- |
| Build | Builds and runs the tests, the example, and `wire_portability` on Linux x86-64, Linux arm64, and macOS arm64 |
| Wire portability | Verifies the presentations from every build job on 32-bit x86 and big-endian s390x Linux under QEMU |
| Container | Builds the `Containerfile` with Podman and runs the tests in it |

## Benchmarks

`build/zklaim/main_benchmark` measures setup, proving, and verification CPU time for 1 to 20 payloads, 30 runs each. It prints every run and appends it to `results-<pid>.csv` in the working directory with the columns: Unix time, payload count, setup ms, proving ms, verification ms, proving key bytes, verification key bytes, proof bytes. A full run takes hours. [Design](design.md#cost) lists typical results.

## Changing the protocol

The wire format, the signed message, the circuit, and the SNARK encodings are part of protocol version 2. Changing any of them requires a new version number, an update of the [wire format specification](wire-format.md), new golden frames in `zklaim/tests/zklaim_deserialize.cpp`, and a migration section. A circuit change also requires every issuer to run a new trusted setup.
