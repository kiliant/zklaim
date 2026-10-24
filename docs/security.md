# Security

This page states what a successful verification establishes, which parties must be trusted, what verifiers must do, and what zklaim does not protect against.

## Guarantees

If `zklaim_ctx_verify` returns `ZKLAIM_OK`, the verifier knows that:

- the presentation's commitments were signed by the trusted issuer key;
- the prover knew attribute values and salts that open those commitments;
- those attribute values satisfy exactly the predicates in the verifier's policy;
- the proof was generated for the verifier's nonce, so it was made in response to this request.

The verifier learns the commitments, the issuer key, the payload count, and that every predicate holds. The proof is zero-knowledge and reveals nothing else about the attributes. The 120-bit salt keeps the commitments from revealing low-entropy attributes to a party that guesses and hashes candidate values.

## Trust assumptions

- **Trusted setup.** Anyone who knows the setup's secret randomness can produce valid proofs for any predicate over any signed commitments. Verifiers must trust whoever ran the setup for the verification key they pin. For an issuer-run setup, that is the issuer. `zklaim_trusted_setup` neither returns nor stores the randomness, but nothing proves that to a verifier.
- **Issuer.** The issuer chooses the attribute values and sees them. A verifier trusts that the issuer certified correct values.
- **Key distribution.** Verifiers obtain the issuer public key and the verification key through a channel they trust, never from a received message.
- **Credential confidentiality.** A credential contains the witnesses. It must travel over a confidential channel, and the prover must store it like a secret: anyone who has the file can present it.
- **Platform.** zklaim relies on libgcrypt's random number generator for salts and nonces and on the correctness of libsnark, libff, libgcrypt, and OpenSSL.

## Verifier checklist

- Pin the issuer public key and verification key per issuer and payload count.
- Derive the expected predicates from your own policy. Never copy them from the received presentation.
- Generate a fresh nonce with `gcry_randomize(nonce, ZKLAIM_NONCE_SIZE, GCRY_STRONG_RANDOM)` for every request, and never accept a second presentation for the same nonce.
- Use `zklaim_ctx_verify`. `zklaim_proof_verify` checks neither the issuer nor the policy.
- Reject every result other than `ZKLAIM_OK`.

## Limitations

- **Linkability.** Every presentation of a credential carries the same commitments and issuer signature, so verifiers that compare presentations can link them to one credential. The issuer key and payload count further narrow the set of possible holders. Applications that need unlinkable presentations can issue several credentials and use each only once. In-circuit signature verification or membership proofs would remove the linkable values but are much more expensive; [#2](https://github.com/kiliant/zklaim/issues/2) discusses the options.
- **No holder binding.** The circuit does not prove knowledge of a holder secret. A credential that leaks can be presented by anyone ([#2](https://github.com/kiliant/zklaim/issues/2)).
- **Relay.** The nonce does not identify the verifier. A malicious verifier can forward another verifier's live request to the holder and pass the presentation on. Binding presentations to a session or verifier identity is the application's responsibility.
- **Predicate expressiveness.** Each attribute is compared with a public constant using one operation. There are no comparisons between attributes, no disjunctions, and no ranges on a single attribute slot.
- **No revocation.** zklaim has no revocation mechanism. An expiry date stored as an attribute, which verifiers check with `zklaim_greater` against the current date, limits a credential's lifetime.
- **Witness hygiene.** The library does not zero freed memory. `zklaim_clear_pres` clears witnesses in a context, and `zklaim_print` writes them to standard output.

## Message parsing

`zklaim_ctx_deserialize` and the SNARK key and proof importers treat their input as untrusted. They check every length against the input size, reject unknown versions, kinds, curves, and operation codes, require canonical encodings, and leave the destination unchanged on failure. The [wire format](wire-format.md) specifies the checks.
