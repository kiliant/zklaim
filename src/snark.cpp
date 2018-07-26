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

#ifndef SNARK_CPP
#define SNARK_CPP

#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <libsnark/common/default_types/r1cs_ppzksnark_pp.hpp>
#include <libff/common/utils.hpp>
#include <boost/optional.hpp>

#include<vector>

using namespace libsnark;
using namespace std;

#include "zklaim_gadget.cpp"

//#include "libsnark_wrapper.cpp"

//bit_vector memtobv(unsigned char, size_t);

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
 * @result 0 on success
 */
    template<typename ppzksnark_ppT>
bool verify_proof(r1cs_gg_ppzksnark_verification_key<ppzksnark_ppT> verification_key,
        r1cs_gg_ppzksnark_proof<ppzksnark_ppT> proof,
        zklaim_ctx *ctx)
{
    typedef Fr<ppzksnark_ppT> FieldT;

    // map given inputs to one input for the algorithm -> primary input
    const r1cs_primary_input<FieldT> input = zklaim_input_map<FieldT>(ctx);

    return r1cs_gg_ppzksnark_verifier_strong_IC<ppzksnark_ppT>(verification_key, input, proof);
}


/**
 * generate the keypair for a given circuit (gadget)
 *
 * the keypair consists of (public) verification and proving keys
 * this only has to be done once, but in a !! trusted !! environment
 * if this is compromised, arbitrary forged (valid!) proofs can be generated
 *
 * @param ctx the context for which to perform trusted setup
 * @result keypair
 */
    template<typename ppzksnark_ppT>
r1cs_gg_ppzksnark_keypair<ppzksnark_ppT> generate_keypair(zklaim_ctx *ctx)
{
    typedef Fr<ppzksnark_ppT> FieldT;
    using namespace std;

    protoboard<FieldT> pb;

    zklaim_gadget<FieldT> g(pb, ctx);
    g.generate_r1cs_constraints();

    const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();

   // cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << endl;

    return r1cs_gg_ppzksnark_generator<ppzksnark_ppT>(constraint_system);
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
 * @result optional<proof>
 */
    template<typename ppzksnark_ppT>
boost::optional<r1cs_gg_ppzksnark_proof<ppzksnark_ppT>> generate_proof(r1cs_gg_ppzksnark_proving_key<ppzksnark_ppT> proving_key,
        zklaim_ctx *ctx)
{
    typedef Fr<ppzksnark_ppT> FieldT;

    protoboard<FieldT> pb;

    zklaim_gadget<FieldT> g(pb, ctx);
    g.generate_r1cs_constraints();

    g.generate_r1cs_witness(ctx);

    // only generate proof if system is satisfied (otherwise proof will be invalid anyways)
    if (!pb.is_satisfied()) {
        cout << "system not satisfied!! not creating proof." << endl;
        return boost::none;
    }

    return r1cs_gg_ppzksnark_prover<ppzksnark_ppT>(proving_key, pb.primary_input(), pb.auxiliary_input());
}

#endif // SNARK_CPP
