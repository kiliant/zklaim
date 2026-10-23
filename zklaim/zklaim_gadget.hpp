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

#ifndef ZKLAIM_GADGET_HPP
#define ZKLAIM_GADGET_HPP

#include <array>
#include <memory>
#include <vector>

#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <libff/algebra/fields/field_utils.hpp>

// libsnark's SHA256 DEBUG diagnostics print the private input block. Disable
// those dumps when including the gadget, preserving DEBUG elsewhere and asserts.
#pragma push_macro("DEBUG")
#undef DEBUG
#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#pragma pop_macro("DEBUG")

typedef std::vector<bool> bit_vector;

/**
 * convert the first len bits of a byte buffer to a bit vector, most significant bit first
 */
inline bit_vector memtobv(const unsigned char* mem, size_t len) {
    bit_vector res(len);
    size_t wordsize = 8;
    for (size_t i = 0; i < len/wordsize; i++) {
        for (size_t k=0; k<wordsize; k++) {
            res[i*wordsize+k] = (*(mem+i) & (1ul << (8-1-k)));
        }
    }
    return res;
}

extern "C" {
#include <zklaim/zklaim.h>
#include <zklaim/zklaim_wire.h>
}

const size_t sha256_digest_len = 256;
const size_t zklaim_pre_bits = ZKLAIM_PRE_SIZE * 8;
const size_t zklaim_nonce_bits = ZKLAIM_NONCE_SIZE * 8;

/* the pre-image and its SHA-256 padding (a one bit, zeros, and the 64-bit length)
 * must fill exactly one block, as a single compression function gadget is used */
static_assert(zklaim_pre_bits + 1 + 64 <= 512, "pre-image must fit one SHA-256 block");

/* Each payload's public input holds its commitment, then 512 bits of references
 * (one 64-bit slot per attribute, zero-padded) and 512 bits of operation flags
 * (one 8-byte group per attribute, one byte per flag, zero-padded). */
enum zklaim_op_flag {
    zklaim_flag_less,
    zklaim_flag_less_or_eq,
    zklaim_flag_eq,
    zklaim_flag_greater_or_eq,
    zklaim_flag_greater,
    zklaim_flag_not_eq,
    zklaim_flag_noop
};

inline void set_zklaim_ops(unsigned char *buf, enum zklaim_op op) {
    switch (op) {
        case zklaim_less: buf[zklaim_flag_less] = 1; break;
        case zklaim_less_or_eq: buf[zklaim_flag_less_or_eq] = 1; break;
        case zklaim_eq: buf[zklaim_flag_eq] = 1; break;
        case zklaim_greater_or_eq: buf[zklaim_flag_greater_or_eq] = 1; break;
        case zklaim_greater: buf[zklaim_flag_greater] = 1; break;
        case zklaim_not_eq: buf[zklaim_flag_not_eq] = 1; break;
        case zklaim_noop: buf[zklaim_flag_noop] = 1; break;
        default: break;
    }
}

/**
 * encode a payload's public references and operation flags, 512 bits each
 */
inline void zklaim_public_bits(const zklaim_payload &pl, bit_vector &refs, bit_vector &ops) {
    unsigned char ref_bytes[64] = {0};
    unsigned char op_bytes[64] = {0};
    for (size_t k = 0; k < ZKLAIM_MAX_PAYLOAD_ATTRIBUTES; k++) {
        zklaim_store_u64(ref_bytes + 8 * k, pl.data_ref[k]);
        set_zklaim_ops(op_bytes + 8 * k, pl.data_op[k]);
    }
    refs = memtobv(ref_bytes, 512);
    ops = memtobv(op_bytes, 512);
}

using namespace libsnark;
using namespace libff;
using namespace std;


/**
 * map the verifier's input to the primary input of the verification algorithm,
 * in the order the gadget packs it
 */
    template<typename FieldT>
r1cs_primary_input<FieldT> zklaim_input_map(zklaim_ctx *ctx, const unsigned char *nonce)
{
    bit_vector input_as_bits, refs, ops;

    for (zklaim_wrap_payload_ctx *cur = ctx->pl_ctx_head; cur != NULL; cur = cur->next) {
        const bit_vector h = memtobv(cur->pl.hash, sha256_digest_len);
        zklaim_public_bits(cur->pl, refs, ops);
        input_as_bits.insert(input_as_bits.end(), h.begin(), h.end());
        input_as_bits.insert(input_as_bits.end(), refs.begin(), refs.end());
        input_as_bits.insert(input_as_bits.end(), ops.begin(), ops.end());
    }
    const bit_vector nonce_vec = memtobv(nonce, zklaim_nonce_bits);
    input_as_bits.insert(input_as_bits.end(), nonce_vec.begin(), nonce_vec.end());

    return pack_bit_vector_into_field_element_vector<FieldT>(input_as_bits);
}


template<typename FieldT>
class zklaim_gadget : public gadget<FieldT> {
    public:
        typedef array<pb_variable<FieldT>, ZKLAIM_MAX_PAYLOAD_ATTRIBUTES> attribute_variables;

        size_t num_of_payloads;
        pb_variable_array<FieldT> input_as_field_elements; /* R1CS input */
        pb_variable_array<FieldT> input_as_bits; /* unpacked R1CS input */

        /* attributes, references and operation flags, and the bits they are packed from */
        pb_variable_array<FieldT> plvars;
        pb_variable_array<FieldT> PL;
        pb_variable_array<FieldT> refvals;
        pb_variable_array<FieldT> REF;
        pb_variable_array<FieldT> opsvals;
        pb_variable_array<FieldT> OPS;

        unique_ptr<multipacking_gadget<FieldT> > unpack_inputs; /* multipacking gadget */

        vector<unique_ptr<digest_variable<FieldT> > > h_vars; /* hashes */
        vector<unique_ptr<digest_variable<FieldT> > > r_vars; /* pre-images */
        vector<unique_ptr<digest_variable<FieldT> > > ref_vals;
        vector<unique_ptr<digest_variable<FieldT> > > ops_vals;
        unique_ptr<digest_variable<FieldT> > nonce_var; /* verifier challenge */

        vector<unique_ptr<block_variable<FieldT> > > h_r_blocks; /* pre-image and padding */
        vector<unique_ptr<sha256_compression_function_gadget<FieldT> > > h_rs; /* pre-image hashes */
        unique_ptr<multipacking_gadget<FieldT> > pack_PL;
        unique_ptr<multipacking_gadget<FieldT> > pack_REF;
        unique_ptr<multipacking_gadget<FieldT> > pack_OPS;

        /* per payload and attribute: the compared value, and the comparison
         * results that the comparison gadget assigns */
        vector<attribute_variables> data, data_less, data_less_or_eq;
        vector<array<unique_ptr<comparison_gadget<FieldT> >, ZKLAIM_MAX_PAYLOAD_ATTRIBUTES> > data_cgs;

        /* field's "zero", for reference */
        pb_variable<FieldT> zero;
        pb_variable_array<FieldT> padding_var; /* SHA-256 padding of the pre-image */

        // The circuit depends only on the payload count, so one trusted setup
        // serves every credential with that count.
        zklaim_gadget(protoboard<FieldT> &pb, size_t num_of_payloads)
            : gadget<FieldT>(pb, "zklaim_gadget")
        {
            this->num_of_payloads = num_of_payloads;

            // allocate space for the verifier input according to the num of payloads given,
            // followed by the verifier's nonce
            const size_t input_size_in_bits = sha256_digest_len * num_of_payloads * 5 + zklaim_nonce_bits;

            const size_t input_size_in_field_elements = div_ceil(input_size_in_bits, FieldT::capacity());
            input_as_field_elements.allocate(pb, input_size_in_field_elements, "input_as_field_elements");

            this->pb.set_input_sizes(input_size_in_field_elements);

            zero.allocate(this->pb, FMT(this->annotation_prefix, "zero"));

            // bits that will be significant to the comparison gadgets
            // chosen to be the full size of the variables
            const size_t comp_b = 64;

            data.resize(num_of_payloads);
            data_less.resize(num_of_payloads);
            data_less_or_eq.resize(num_of_payloads);
            for (size_t i = 0; i < num_of_payloads; i++) {
                for (size_t k = 0; k < ZKLAIM_MAX_PAYLOAD_ATTRIBUTES; k++) {
                    data[i][k].allocate(this->pb, "data");
                    data_less[i][k].allocate(this->pb, "data_less");
                    data_less_or_eq[i][k].allocate(this->pb, "data_less_or_eq");
                }
            }

            // input variable assignment, for sanity check -> prover does not manipulate values
            // we get from the pre-image of the hash
            plvars.allocate(this->pb, ZKLAIM_MAX_PAYLOAD_ATTRIBUTES * num_of_payloads, "input validation");
            refvals.allocate(this->pb, 8 * num_of_payloads, "input validation");
            opsvals.allocate(this->pb, 64 * num_of_payloads, "operation values");

            // SHA-256 padding: a one bit, zeros, and the big-endian 64-bit message length
            const size_t padding_bits = 512 - zklaim_pre_bits;
            for (size_t i = 0; i < padding_bits; i++) {
                const size_t length_bit = padding_bits - 1 - i;
                const bool bit = i == 0 || (length_bit < 64 && ((zklaim_pre_bits >> length_bit) & 1));
                padding_var.emplace_back(bit ? ONE : zero);
            }

            // verifier (and prover) inputs:
            for (size_t i = 0; i<num_of_payloads; i++) {
                h_vars.emplace_back(new digest_variable<FieldT>(this->pb, sha256_digest_len, "h"));
                ref_vals.emplace_back(new digest_variable<FieldT>(this->pb, sha256_digest_len * 2, "h"));
                ops_vals.emplace_back(new digest_variable<FieldT>(this->pb, sha256_digest_len * 2, "h"));
                input_as_bits.insert(input_as_bits.end(), h_vars.back()->bits.begin(), h_vars.back()->bits.end());
                input_as_bits.insert(input_as_bits.end(), ref_vals.back()->bits.begin(), ref_vals.back()->bits.end());
                input_as_bits.insert(input_as_bits.end(), ops_vals.back()->bits.begin(), ops_vals.back()->bits.end());
            }
            // The packing below constrains the nonce bits, binding the proof to them.
            nonce_var.reset(new digest_variable<FieldT>(this->pb, zklaim_nonce_bits, "nonce"));
            input_as_bits.insert(input_as_bits.end(), nonce_var->bits.begin(), nonce_var->bits.end());

            // multipacking
            assert(input_as_bits.size() == input_size_in_bits);
            unpack_inputs.reset(new multipacking_gadget<FieldT>(this->pb,
                        input_as_bits,
                        input_as_field_elements,
                        FieldT::capacity(),
                        FMT(this->annotation_prefix, "unpack_inputs")));

            // prover inputs:
            for (size_t i = 0; i<num_of_payloads; i++) {
                r_vars.emplace_back(new digest_variable<FieldT>(this->pb, zklaim_pre_bits, "r"));
                // SHA-256 consumes big-endian words; multipacking consumes
                // least-significant bits first. Reverse each complete uint64.
                // The salt is only hashed, so it is not packed.
                for (size_t slot = 0; slot < ZKLAIM_MAX_PAYLOAD_ATTRIBUTES; ++slot) {
                    for (int bit = 63; bit >= 0; --bit) {
                        PL.emplace_back(r_vars.back()->bits[slot * 64 + bit]);
                    }
                }
            }

            for (size_t i=0; i<num_of_payloads; i++) {
                for (size_t slot = 0; slot < 8; ++slot) {
                    for (int bit = 63; bit >= 0; --bit) {
                        REF.emplace_back(ref_vals[i]->bits[slot * 64 + bit]);
                    }
                }
            }

            for (size_t i=0; i<num_of_payloads; i++) {
                for (int l = 0; l<64; l++) {
                    for (int k=7; k>=0; k--) {
                        OPS.insert(OPS.end(), ops_vals[i]->bits.begin()+k+l*8, ops_vals[i]->bits.begin()+k+1+l*8);
                    }
                }
            }


            // IV for SHA256
            pb_linear_combination_array<FieldT> IV = SHA256_default_IV(pb);

            pack_PL.reset(new multipacking_gadget<FieldT>(pb, PL, plvars, 64, FMT(this->annotation_prefix, "pack payload")));
            pack_REF.reset(new multipacking_gadget<FieldT>(pb, REF, refvals, 64, FMT(this->annotation_prefix, "pack payload")));
            pack_OPS.reset(new multipacking_gadget<FieldT>(pb, OPS, opsvals, 8, FMT(this->annotation_prefix, "pack payload")));

            // hash each pre-image, padded to one block
            for (size_t i = 0; i < num_of_payloads; i++) {
                h_r_blocks.emplace_back(new block_variable<FieldT>(this->pb, {
                            r_vars[i]->bits,
                            padding_var
                            }, "h_r1_block"));

                h_rs.emplace_back(new sha256_compression_function_gadget<FieldT>(this->pb,
                            IV,
                            h_r_blocks[i]->bits,
                            *h_vars[i],
                            "h_r1"));
            }

            // compare each attribute with its public reference value
            data_cgs.resize(num_of_payloads);
            for (size_t i=0; i<num_of_payloads; i++) {
                for (size_t k = 0; k < ZKLAIM_MAX_PAYLOAD_ATTRIBUTES; k++) {
                    data_cgs[i][k].reset(new comparison_gadget<FieldT>(this->pb,
                                comp_b,
                                data[i][k],
                                refvals[k + i*8],
                                data_less[i][k],
                                data_less_or_eq[i][k],
                                "data cmp gadget"));
                }
            }
        }

        /**
         * generate R1 Constraint System for the gadget
         */
        void generate_r1cs_constraints()
        {
            // multipacking gadget constraints (for input validation)
            unpack_inputs->generate_r1cs_constraints(true);

            // bind the values used in the comparisons to the hashed pre-image (PL) and to the
            // public reference values (REF) and operations (OPS); without these, prover can
            // choose them freely. bitness is already enforced via r_vars and unpack_inputs
            pack_PL->generate_r1cs_constraints(false);
            pack_REF->generate_r1cs_constraints(false);
            pack_OPS->generate_r1cs_constraints(false);

            // sanity check
            generate_r1cs_equals_const_constraint<FieldT>(this->pb, zero, FieldT::zero(), "zero");

            for (size_t i=0; i < this->num_of_payloads; i++) {
                r_vars[i]->generate_r1cs_constraints();

                // activate the comparison gadget
                // this is needed such that less and less_or_eq are set
                for (size_t k = 0; k < ZKLAIM_MAX_PAYLOAD_ATTRIBUTES; k++) {
                    data_cgs[i][k]->generate_r1cs_constraints();
                }

                // a set operation flag requires the corresponding comparison result:
                // flag * result = flag
                for (size_t k = 0; k < ZKLAIM_MAX_PAYLOAD_ATTRIBUTES; k++) {
                    const pb_variable<FieldT> less = data_less[i][k];
                    const pb_variable<FieldT> less_or_eq = data_less_or_eq[i][k];
                    const auto flag = [&](zklaim_op_flag f) { return opsvals[f + k*8 + i*64]; };
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(flag(zklaim_flag_less), less, flag(zklaim_flag_less)), "op_less");
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(flag(zklaim_flag_less_or_eq), less_or_eq, flag(zklaim_flag_less_or_eq)), "op_less_or_eq");
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(flag(zklaim_flag_eq), less_or_eq, flag(zklaim_flag_eq)), "op_eq #1");
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(flag(zklaim_flag_eq), less, 0), "op_eq #2");
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(flag(zklaim_flag_greater_or_eq), 1 - less, flag(zklaim_flag_greater_or_eq)), "op_greater_or_eq");
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(flag(zklaim_flag_greater), 1 - less_or_eq, flag(zklaim_flag_greater)), "op_greater");
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(flag(zklaim_flag_not_eq), less + (1 - less_or_eq), flag(zklaim_flag_not_eq)), "op_not_eq");
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(flag(zklaim_flag_noop), 1, flag(zklaim_flag_noop)), "op_noop");
                }

                // ensure mutual exclusion
                for (size_t k = 0; k < ZKLAIM_MAX_PAYLOAD_ATTRIBUTES; k++) {
                    const auto flag = [&](zklaim_op_flag f) { return opsvals[f + k*8 + i*64]; };
                    this->pb.add_r1cs_constraint(
                            r1cs_constraint<FieldT>(1,
                                flag(zklaim_flag_less)
                                + flag(zklaim_flag_less_or_eq)
                                + flag(zklaim_flag_eq)
                                + flag(zklaim_flag_greater_or_eq)
                                + flag(zklaim_flag_greater)
                                + flag(zklaim_flag_not_eq)
                                + flag(zklaim_flag_noop), 1), "consistency check");
                }

                // enforce that what we compare is also contained in the input at the
                // right slot
                for (size_t k = 0; k < ZKLAIM_MAX_PAYLOAD_ATTRIBUTES; k++) {
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, data[i][k] - plvars[k + i*ZKLAIM_MAX_PAYLOAD_ATTRIBUTES], 0), "input validation");
                }

                // constraint to ensure the hashes validate.
                h_rs[i]->generate_r1cs_constraints();
            }
        }

        /**
         * generate witnesses for the constraint system of this gadget
         * need to provide assignment to necessary variables
         */
        void generate_r1cs_witness(zklaim_ctx *ctx, const unsigned char *nonce)
        {
            this->pb.val(zero) = FieldT::zero();
            // fill pre-image with witnessed data
            bit_vector refs, ops;
            size_t i = 0;
            for (zklaim_wrap_payload_ctx *cur = ctx->pl_ctx_head;
                 cur != NULL && i < this->num_of_payloads; cur = cur->next, i++) {
                zklaim_public_bits(cur->pl, refs, ops);
                r_vars[i]->bits.fill_with_bits(this->pb, memtobv(cur->pl.pre, zklaim_pre_bits));

                // generate witness for other gadgets in use (hash gadget, etc.)
                h_rs[i]->generate_r1cs_witness();
                h_vars[i]->bits.fill_with_bits(this->pb, memtobv(cur->pl.hash, sha256_digest_len));
                ref_vals[i]->bits.fill_with_bits(this->pb, refs);
                ops_vals[i]->bits.fill_with_bits(this->pb, ops);
            }

            nonce_var->bits.fill_with_bits(this->pb, memtobv(nonce, zklaim_nonce_bits));
            unpack_inputs->generate_r1cs_witness_from_bits();
            pack_REF->generate_r1cs_witness_from_bits();
            pack_OPS->generate_r1cs_witness_from_bits();

            pack_PL->generate_r1cs_witness_from_bits();

            for (size_t i=0; i<this->num_of_payloads; i++) {
                for (size_t k = 0; k < ZKLAIM_MAX_PAYLOAD_ATTRIBUTES; k++) {
                    // Take numeric values from the constrained packing instead of
                    // converting uint64_t to native long (which truncates on 32-bit
                    // machines and sign-extends values above INT64_MAX).
                    this->pb.val(data[i][k]) = this->pb.val(plvars[k + i*ZKLAIM_MAX_PAYLOAD_ATTRIBUTES]);
                    data_cgs[i][k]->generate_r1cs_witness();
                }
            }
        }
};

#endif // ZKLAIM_GADGET_HPP
