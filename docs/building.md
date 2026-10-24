# Building

zklaim builds with CMake on x86-64 and arm64, on Linux and macOS.

## Requirements

- C and C++11 compilers
- CMake 3.13 or newer
- pkg-config
- GMP, including its C++ bindings (`gmpxx`)
- libgcrypt
- OpenSSL 3.0 or newer

OpenSSL 3.0 is the first version under the Apache License 2.0, which is compatible with zklaim's LGPL; the license of earlier versions is not. On systems that still ship OpenSSL 1.1.1, such as RHEL 8, install OpenSSL 3 separately and pass its prefix as `-DOPENSSL_ROOT_DIR=...` when configuring.

Install them with:

- Debian/Ubuntu: `sudo apt-get install build-essential cmake git pkg-config libgmp-dev libgcrypt20-dev libssl-dev`
- Arch Linux: `sudo pacman -S --needed base-devel cmake git gmp libgcrypt openssl`
- macOS (Homebrew): `brew install cmake gmp libgcrypt openssl@3 pkgconf`

## Get the source

libsnark and googletest are Git submodules:

```sh
git clone https://github.com/kiliant/zklaim.git
cd zklaim
git submodule update --init --recursive
```

Run the submodule command again after pulling new commits to check out the pinned versions. If an earlier attempt failed on `git://` URLs, run `git submodule sync --recursive` first.

## Configure and build

```sh
cmake -S . -B build
cmake --build build --parallel
```

On macOS, point CMake to Homebrew's OpenSSL: `cmake -S . -B build -DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3)`.

The build produces, in `build/zklaim/`:

| File | Purpose |
| --- | --- |
| `libzklaim.so` or `libzklaim.dylib` | The library |
| `main` | Example run of issuer, prover, and verifier |
| `main_benchmark` | Benchmark, see [Development](development.md#benchmarks) |
| `bttestc` | Unit tests, see [Development](development.md#tests) |
| `wire_portability` | Cross-platform presentation fixture tool |

Run the example with `build/zklaim/main`.

## Options

Pass options as `-D<option>=<value>` when configuring.

| Option | Default | Effect |
| --- | --- | --- |
| `CMAKE_BUILD_TYPE` | `RelWithDebInfo` | CMake build type |
| `CURVE` | `ALT_BN128` | Pairing curve: `ALT_BN128`, `BN128` (x86-64 only), `EDWARDS`, `MNT4`, or `MNT6` |
| `OPT_FLAGS` | empty | Additional C++ compiler flags, e.g. `-march=native` for binaries tuned to, and only runnable on, the build machine |
| `MULTICORE` | `OFF` | Parallelize libff and libsnark with OpenMP |
| `WITH_PROCPS` | `OFF` | Memory profiling through `libprocps` |
| `USE_ASM` | `ON` | libff's architecture-specific assembly; CI turns it off for 32-bit x86 and s390x |

The curve is part of the protocol: messages record it, and a library built for another curve rejects them. All issuers, provers, and verifiers that interoperate must use the same `CURVE`.

`lib/CMakeLists.txt` forces libff's `BINARY_OUTPUT`, `MONTGOMERY_OUTPUT`, and `USE_PT_COMPRESSION` options off. They select the canonical encoding of keys and proofs that the [wire format](wire-format.md#snark-keys-and-proofs) specifies and cannot be changed.

## Install and link

```sh
cmake --install build --prefix "$PREFIX"
```

This installs the headers to `$PREFIX/include/zklaim/` and the shared library to `$PREFIX/lib/`. Include `<zklaim/zklaim.h>` and link with `-lzklaim -lgcrypt`:

```sh
cc app.c -o app -I"$PREFIX/include" -L"$PREFIX/lib" -lzklaim \
    $(pkg-config --cflags --libs libgcrypt) -Wl,-rpath,"$PREFIX/lib"
```

The `-rpath` flag is needed only if `$PREFIX/lib` is not in the dynamic linker's search path. libff is linked statically into `libzklaim`, which exports only the functions marked `ZKLAIM_API`.

## Container

The `Containerfile` builds and installs zklaim on Arch Linux and runs the tests:

```sh
podman build -t zklaim .
podman run --rm zklaim
```

With Docker: `docker build -f Containerfile -t zklaim .` and `docker run --rm zklaim`.
