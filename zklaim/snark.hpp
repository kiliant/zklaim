/*
 * This file is part of zklaim.
 * zklaim is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * zklaim is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with zklaim. If not, see https://www.gnu.org/licenses/.
 */

#ifndef ZKLAIM_SNARK_HPP
#define ZKLAIM_SNARK_HPP

#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>
#include <libff/common/utils.hpp>
#include <libfqfft/evaluation_domain/get_evaluation_domain.hpp>

#include<vector>

using namespace libsnark;
using namespace std;

#include "zklaim_gadget.hpp"

extern "C" {
#include <zklaim/zklaim.h>
}


/**
 * verify a given proof using given verification key and primary inputs
 *
 * this is done solely by the verifier, will only work if the prover had valid witnesses
 *
 * @param verification_key the verification key
 * @param proof the proof to verify
 * @param ctx the context from which to extract the public input
 * @param nonce the verifier's challenge, also part of the public input
 * @result true if the proof is valid
 */
    template<typename ppzksnark_ppT>
bool verify_proof(r1cs_gg_ppzksnark_verification_key<ppzksnark_ppT> verification_key,
        r1cs_gg_ppzksnark_proof<ppzksnark_ppT> proof,
        zklaim_ctx *ctx, const unsigned char *nonce)
{
    typedef Fr<ppzksnark_ppT> FieldT;

    // map given inputs to one input for the algorithm -> primary input
    const r1cs_primary_input<FieldT> input = zklaim_input_map<FieldT>(ctx, nonce);

    // A key for another payload count cannot verify; libsnark would print this.
    if (verification_key.gamma_ABC_g1.domain_size() != input.size()) {
        return false;
    }
    return r1cs_gg_ppzksnark_verifier_strong_IC<ppzksnark_ppT>(verification_key, input, proof);
}


/**
 * generate the keypair for a given circuit (gadget)
 *
 * the keypair consists of (public) verification and proving keys
 * this only has to be done once per payload count, but in a !! trusted !! environment
 * if this is compromised, arbitrary forged (valid!) proofs can be generated
 *
 * @param num_of_payloads the payload count for which to perform trusted setup
 * @result keypair
 */
    template<typename ppzksnark_ppT>
r1cs_gg_ppzksnark_keypair<ppzksnark_ppT> generate_keypair(size_t num_of_payloads)
{
    typedef Fr<ppzksnark_ppT> FieldT;
    using namespace std;

    protoboard<FieldT> pb;

    zklaim_gadget<FieldT> g(pb, num_of_payloads);
    g.generate_r1cs_constraints();

    const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();

   // cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << endl;

    return r1cs_gg_ppzksnark_generator<ppzksnark_ppT>(constraint_system);
}


/**
 * check that a proving key belongs to the given circuit
 *
 * the prover indexes the key's vectors by the circuit's sizes and checks them
 * only in debug builds, so a key for another circuit must not reach it
 */
template<typename T>
bool valid_sparse_vector(const sparse_vector<T> &vector)
{
    if (vector.indices.size() != vector.values.size() ||
        vector.indices.size() > vector.domain_size()) return false;
    for (size_t i = 0; i < vector.indices.size(); ++i) {
        if (vector.indices[i] >= vector.domain_size() ||
            (i > 0 && vector.indices[i - 1] >= vector.indices[i])) return false;
    }
    return true;
}

    template<typename ppzksnark_ppT>
bool proving_key_matches(const r1cs_gg_ppzksnark_proving_key<ppzksnark_ppT> &proving_key,
        const r1cs_constraint_system<Fr<ppzksnark_ppT> > &constraint_system)
{
    typedef Fr<ppzksnark_ppT> FieldT;
    const size_t variables = constraint_system.num_variables();
    const size_t degree = libfqfft::get_evaluation_domain<FieldT>(
        constraint_system.num_constraints() + constraint_system.num_inputs() + 1)->m;
    // The generator may swap A and B in every constraint, which keeps the
    // relation A * B = C; its helper for that decision prints to stdout.
    r1cs_constraint_system<FieldT> swapped = constraint_system;
    for (auto &constraint : swapped.constraints) {
        std::swap(constraint.a, constraint.b);
    }
    return (proving_key.constraint_system == constraint_system ||
            proving_key.constraint_system == swapped) &&
        proving_key.A_query.size() == variables + 1 &&
        proving_key.B_query.domain_size() == variables + 1 &&
        valid_sparse_vector(proving_key.B_query) &&
        proving_key.H_query.size() == degree - 1 &&
        proving_key.L_query.size() == variables - constraint_system.num_inputs();
}


/**
 * generate a proof for given circuit, primary, auxiliary inputs
 *
 * this is done solely by the prover
 * primary input: also known by the verifyer (e.g. hash value)
 * auxiliary input: non-deterministic helper information for the algorithm
 * circuit: on which the proof shall be based upon
 *
 * @param proving_key the proving key to utilize
 * @param ctx the context from which to extract public and private inputs
 * @param nonce the verifier's challenge to bind the proof to
 * @param proof receives the generated proof
 * @result true if a proof was generated, false if the proving key belongs to
 *         another circuit or the constraint system is not satisfied
 */
    template<typename ppzksnark_ppT>
bool generate_proof(const r1cs_gg_ppzksnark_proving_key<ppzksnark_ppT> &proving_key,
        zklaim_ctx *ctx, const unsigned char *nonce, r1cs_gg_ppzksnark_proof<ppzksnark_ppT> &proof)
{
    typedef Fr<ppzksnark_ppT> FieldT;

    protoboard<FieldT> pb;

    zklaim_gadget<FieldT> g(pb, ctx->num_of_payloads);
    g.generate_r1cs_constraints();
    if (!proving_key_matches<ppzksnark_ppT>(proving_key, pb.get_constraint_system())) {
        return false;
    }

    g.generate_r1cs_witness(ctx, nonce);

    // only generate proof if system is satisfied (otherwise proof will be invalid anyways)
    if (!pb.is_satisfied()) {
        cout << "system not satisfied!! not creating proof." << endl;
        return false;
    }

    proof = r1cs_gg_ppzksnark_prover<ppzksnark_ppT>(proving_key, pb.primary_input(), pb.auxiliary_input());
    return true;
}

#endif // ZKLAIM_SNARK_HPP
