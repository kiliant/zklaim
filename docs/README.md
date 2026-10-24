# zklaim documentation

zklaim is a C library for zero-knowledge credentials: an issuer signs commitments to a holder's numeric attributes, and the holder proves predicates over them, such as "born before 2008", to verifiers without revealing the values.

| Page | Covers |
| --- | --- |
| [Concepts](concepts.md) | Roles, payloads, predicates, credentials and presentations, trusted setup, nonces, and the protocol flow |
| [Building](building.md) | Requirements, build options, installing and linking, container builds |
| [Developer guide](guide.md) | Issuing, requesting, proving, and verifying, step by step with code |
| [API reference](api.md) | Every public type, constant, and function |
| [Security](security.md) | Guarantees, trust assumptions, verifier checklist, and limitations |
| [Design](design.md) | The proven statement, circuit, public input layout, and measured cost |
| [Wire format](wire-format.md) | Byte-level specification of credentials, presentations, signatures, keys, and migration from version 1 |
| [Development](development.md) | Repository layout, tests, CI, benchmarks, and protocol changes |

## Where to start

- **Integrating zklaim:** [Concepts](concepts.md), then [Building](building.md) and the [developer guide](guide.md), with the [API reference](api.md) at hand.
- **Accepting credentials as a verifier:** the [verifier checklist](security.md#verifier-checklist) and the [verification step](guide.md#verifier-verification).
- **Implementing the format in another language:** the [wire format](wire-format.md) and the [public input layout](design.md#public-input-layout).
- **Contributing:** [Development](development.md) and [Design](design.md).
