# zklaim

[![CI](https://github.com/kiliant/zklaim/actions/workflows/ci.yml/badge.svg)](https://github.com/kiliant/zklaim/actions/workflows/ci.yml)

## Instructions
1. install dependencies (C/C++ compiler, CMake >= 3.13, pkg-config, GMP, libgcrypt, OpenSSL >= 1.1.1)
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

An issuer runs the trusted setup once for each payload count it supports and reuses the keys for every credential with that count:

```c
unsigned char *pk, *vk;
size_t pk_size, vk_size;
if (zklaim_trusted_setup(1, &pk, &pk_size, &vk, &vk_size) != ZKLAIM_OK) { /* handle error */ }
```

Provers receive the proving key and pass it to `zklaim_proof_generate`. Verifiers pin the verification key per issuer and payload count. Whoever runs the setup can forge proofs, so verifiers must trust that party, normally the issuer.

Credential verification requires the issuer public key and verification key from the verifier's trusted configuration, an expected predicate for every payload in payload order, and a fresh nonce. For example, a verifier requiring attribute 0 to be at least 18 in a single-payload credential first sends its predicate and a random nonce to the prover:

```c
unsigned char nonce[ZKLAIM_NONCE_SIZE];
gcry_randomize(nonce, sizeof(nonce), GCRY_STRONG_RANDOM);
```

The prover applies the predicate, calls `zklaim_proof_generate(ctx, pk, pk_size, nonce)`, and returns the presentation, which the verifier checks with:

```c
int accept_age_credential(zklaim_ctx *received,
                          const unsigned char trusted_issuer_key[32],
                          const unsigned char *trusted_vk, size_t trusted_vk_size,
                          const unsigned char nonce[ZKLAIM_NONCE_SIZE]) {
    const zklaim_predicate expected[] = {
        {{18, 0, 0, 0, 0},
         {zklaim_greater_or_eq, zklaim_noop, zklaim_noop, zklaim_noop, zklaim_noop}}
    };
    return zklaim_ctx_verify(received, trusted_issuer_key, trusted_vk, trusted_vk_size,
                             expected, sizeof(expected) / sizeof(expected[0]), nonce);
}
```

The issuer key uses the 32-byte encoding returned by `zklaim_pub2buf`. Obtain both keys through a trusted channel; never select the trusted key from `received->pub_key`. Define the expected references and operations from the verifier's policy, and send that request to the prover. Verification requires an exact match for every attribute (including `noop` slots) and the payload count, followed by a valid issuer signature and a proof for the verifier's nonce. Do not build the expected predicates by copying the received context, and never reuse a nonce: a presentation proved for one nonce fails for every other, which stops a verifier from replaying presentations it received.

An issuer mismatch returns `ZKLAIM_UNTRUSTED_ISSUER`; a predicate or payload-count mismatch returns `ZKLAIM_UNEXPECTED_PREDICATE`; a proof for another nonce or verification key returns `ZKLAIM_INVALID_PROOF`. `zklaim_proof_verify` is a low-level proof check: it does not authenticate an issuer or enforce the verifier's policy.

`zklaim_ctx_serialize` produces a version 2 presentation with no witness or salt fields, even if the source still contains private attributes. For confidential issuer-to-prover transfer, use `zklaim_ctx_serialize_credential` explicitly. Both kinds are read by `zklaim_ctx_deserialize`. Attribute pre-images use big-endian integers followed by a 15-byte random salt; use `zklaim_set_attr` and `zklaim_get_attr` to access the attributes.

Version 2 changes the API and wire format: setup keys are no longer stored in `zklaim_ctx` or serialized, salts grew from 8 to 15 bytes, and proofs are bound to a nonce. Version 1 messages are rejected: rerun the trusted setup per payload count and reissue credentials; issuer signing keys stay valid. See the [wire format and migration specification](docs/wire-format.md) for field offsets, signature inputs, canonical SNARK encoding, and private-key seed storage.


## Run the Tests
The (unit) tests are run automatically by GitHub Actions on Linux (x86-64, arm64), macOS (arm64) and in the Arch Linux container for every push to master and every pull request.

CI also exchanges real signed presentation fixtures and their verification keys between Linux and macOS and verifies them on 32-bit x86 and big-endian s390x Linux. To exercise a fixture locally: `build/zklaim/wire_portability issue /tmp/presentation.zkp /tmp/presentation.vk` followed by `build/zklaim/wire_portability verify /tmp/presentation.zkp /tmp/presentation.vk`.

To run tests locally, a custom target for this implementation has been implemented:

1. follow the build instructions above
2. ``cmake --build build --target bttest``
3. an overview of the tests (if successful etc.) will be displayed

To build and test in a container instead: ``podman build -t zklaim . && podman run --rm zklaim`` (with Docker: ``docker build -f Containerfile -t zklaim .``).

Google's (unit) testing framework is used as a backend.

TODO
