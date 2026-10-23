# zklaim

[![CI](https://github.com/kiliant/zklaim/actions/workflows/ci.yml/badge.svg)](https://github.com/kiliant/zklaim/actions/workflows/ci.yml)

## Instructions
1. install dependencies (C/C++ compiler, CMake >= 3.13, pkg-config, GMP, libgcrypt, OpenSSL)
    - on Debian/Ubuntu: ``sudo apt-get install build-essential cmake git pkg-config libgmp-dev libgcrypt20-dev libssl-dev``
    - on Arch Linux: ``sudo pacman -S --needed base-devel cmake git gmp libgcrypt openssl``
    - on macOS (Homebrew): ``brew install cmake gmp libgcrypt openssl@3 pkgconf``
2. clone this repo ;)
3. to pull in the submodules: ``git submodule update --init --recursive``
    - if an earlier attempt failed on ``git://`` URLs, run ``git submodule sync --recursive`` first
4. after pulling new commits, update the submodules to the pinned versions with the same command


## Run the Example
1. follow the steps above
2. configure: ``cmake -S . -B build``
    - on macOS, point CMake to Homebrew's OpenSSL: ``cmake -S . -B build -DOPENSSL_ROOT_DIR=$(brew --prefix openssl@3)``
3. build: ``cmake --build build --parallel``
4. run example at ``build/zklaim/main``

The build works on x86-64 and arm64 (Linux and macOS). Useful options (pass as ``-D<option>=<value>`` when configuring):

- ``CMAKE_BUILD_TYPE``: defaults to ``RelWithDebInfo``
- ``OPT_FLAGS``: additional C++ compiler flags, e.g. ``-march=native`` for binaries tuned to (and only runnable on) the build machine
- ``CURVE``: one of ``ALT_BN128`` (default), ``BN128`` (x86-64 only), ``EDWARDS``, ``MNT4``, ``MNT6``
- ``MULTICORE``: parallelize libff/libsnark using OpenMP (default ``OFF``)
- ``WITH_PROCPS``: memory profiling via ``libprocps`` (default ``OFF``)


## Use the Library
``cmake --install build`` installs ``libzklaim`` and its headers (``#include <zklaim/zklaim.h>``). Link your program with ``-lzklaim -lgcrypt``.

Credential verification requires an issuer public key from the verifier's trusted configuration and an expected predicate for every payload, in payload order. For example, a verifier requiring attribute 0 to be at least 18 in a single-payload credential can use:

```c
int accept_age_credential(zklaim_ctx *received,
                          const unsigned char trusted_issuer_key[32]) {
    const zklaim_predicate expected[] = {
        {{18, 0, 0, 0, 0},
         {zklaim_greater_or_eq, zklaim_noop, zklaim_noop, zklaim_noop, zklaim_noop}}
    };
    return zklaim_ctx_verify(received, trusted_issuer_key, expected,
                             sizeof(expected) / sizeof(expected[0]));
}
```

The key uses the 32-byte encoding returned by `zklaim_pub2buf`. Obtain it through a trusted channel; never select the trusted key from `received->pub_key`. Define the expected references and operations from the verifier's policy, and send that request to the prover. Verification requires an exact match for every attribute (including `noop` slots) and the payload count, followed by a valid issuer signature and proof. Do not build the expected predicates by copying the received context.

This replaces the former one-argument `zklaim_ctx_verify(ctx)` API. Migrate callers to pass the trusted key, expected predicates, and predicate count. An issuer mismatch returns `ZKLAIM_UNTRUSTED_ISSUER`; a predicate or payload-count mismatch returns `ZKLAIM_UNEXPECTED_PREDICATE`. `zklaim_proof_verify` is a low-level proof check: it does not authenticate an issuer or enforce the verifier's policy.


## Run the Tests
The (unit) tests are run automatically by GitHub Actions on Linux (x86-64, arm64), macOS (arm64) and in the Arch Linux container for every push to master and every pull request.

To run tests locally, a custom target for this implementation has been implemented:

1. follow the build instructions above
2. ``cmake --build build --target bttest``
3. an overview of the tests (if successful etc.) will be displayed

To build and test in a container instead: ``podman build -t zklaim . && podman run --rm zklaim`` (with Docker: ``docker build -f Containerfile -t zklaim .``).

Google's (unit) testing framework is used as a backend.

TODO
