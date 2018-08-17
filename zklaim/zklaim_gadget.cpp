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


#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <libff/algebra/fields/field_utils.hpp>

typedef std::vector<bool> bit_vector;

bit_vector memtobv(unsigned char*, size_t);

extern "C" {
#include <zklaim/zklaim.h>
}

const size_t sha256_digest_len = 256;

/* this is needed as a 2-to-1-compression sha256-gadget is used, thus we pad our input to 512 */
bool sha256_padding[128] = {1,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,1, 1,0,0,0,0,0,0,0};

bool debug = false;

uint64_t extractFromBV(const libff::bit_vector &r, uint8_t slot_offset) {
    uint64_t var = 0;

    if (slot_offset > 5) {
        printf("current construction only allows 3 elements in a zklaim payload!\n");
        printf("returning -1 dummy value\n");
        return -1;
    }

    // recovering age from bitvector
    for (size_t i = 0; i < 8; i++) {
        for (size_t k=0; k < 8; k++) {
            if (debug)
                printf("%d ", r[slot_offset*64+i*8+k]);
            var |= (uint64_t) r[slot_offset*64+i*8+k] << (8-1+i*8-k);
        }
    }
    if (debug) {
        printf("\n");

        for (size_t i = 0; i < 8; i++) {
            uint8_t tmp = ((uint64_t) var >> i*8) & 0xff;
            for (size_t k=0; k < 8; k++) {
                printf("%lu ", (tmp >> k) & (1ul));
            }
        }
    }

    return var;
}

void set_zklaim_ops(unsigned char *buf, enum zklaim_op op) {
    uint8_t val = 0x1;
    switch (op) {
        case zklaim_less:
            // <
            *(buf+0) = val;
            break;
        case zklaim_less_or_eq:
            // <=
            *(buf+1) = val;
            break;
        case zklaim_eq:
            // equality
            *(buf+2) = val;
            break;
        case zklaim_greater_or_eq:
            // >=
            *(buf+3) = val;
            break;
        case zklaim_greater:
            // >
            *(buf+4) = val;
            break;
        case zklaim_not_eq:
            // ineq
            *(buf+5) = val;
            break;
        case zklaim_noop:
            *(buf+6) = val;
            break;
        default:
            break;
    }
}

using namespace libsnark;
using namespace libff;
using namespace std;


/**
 *  this is needed as to map the verifiers input to a single primary input for the verification algorithm
 *  this also has to be adapted for possibly changed inputs the verifier might have
 */
    template<typename FieldT>
r1cs_primary_input<FieldT> zklaim_input_map(zklaim_ctx *ctx)
{
    bit_vector input_as_bits, h, refs_vec, ops_vec;
    unsigned char refs[512] = {0};
    unsigned char ops[512];
    zklaim_wrap_payload_ctx *cur = ctx->pl_ctx_head;

    while (cur != NULL) {
        // construct reference buf
        memset(refs, 0, 512);
        memcpy(refs, &cur->pl.data_ref[0], 8);
        memcpy(refs+8, &cur->pl.data_ref[1], 8);
        memcpy(refs+16, &cur->pl.data_ref[2], 8);
        memcpy(refs+24, &cur->pl.data_ref[3], 8);
        memcpy(refs+32, &cur->pl.data_ref[4], 8);

        memset(ops, 0, 512);
        set_zklaim_ops(ops, cur->pl.data_op[0]);
        set_zklaim_ops(ops+8, cur->pl.data_op[1]);
        set_zklaim_ops(ops+16, cur->pl.data_op[2]);
        set_zklaim_ops(ops+24, cur->pl.data_op[3]);
        set_zklaim_ops(ops+32, cur->pl.data_op[4]);

        h = memtobv(cur->pl.hash, 256);
        refs_vec = memtobv(refs, 512);
        ops_vec = memtobv(ops, 512);
        input_as_bits.insert(input_as_bits.end(), h.begin(), h.end());
        input_as_bits.insert(input_as_bits.end(), refs_vec.begin(), refs_vec.end());
        input_as_bits.insert(input_as_bits.end(), ops_vec.begin(), ops_vec.end());
        cur = cur->next;
    }

    vector<FieldT> input_as_field_elements = pack_bit_vector_into_field_element_vector<FieldT>(input_as_bits);
    return input_as_field_elements;
}


template<typename FieldT>
class zklaim_gadget : public gadget<FieldT> {
    public:
        uint64_t num_of_payloads;
        pb_variable_array<FieldT> input_as_field_elements; /* R1CS input */
        pb_variable_array<FieldT> input_as_bits; /* unpacked R1CS input */

        pb_variable_array<FieldT> plvars;
        pb_variable_array<FieldT> PL;
        pb_variable_array<FieldT> refvals;
        pb_variable_array<FieldT> REF;
        pb_variable_array<FieldT> opsvals;
        pb_variable_array<FieldT> OPS;

        shared_ptr<multipacking_gadget<FieldT> > unpack_inputs; /* multipacking gadget */

        vector<digest_variable<FieldT>*> h_vars; /* hashes */
        vector<digest_variable<FieldT>*> r_vars; /* pre-images */
        vector<digest_variable<FieldT>*> ref_vals;
        vector<digest_variable<FieldT>*> ops_vals;

        vector<block_variable<FieldT>*> h_r_blocks; /* 512 bit block that contains r1 + padding */
        vector<sha256_compression_function_gadget<FieldT>*> h_rs; /* hashing gadget for r1 */
        shared_ptr<multipacking_gadget<FieldT> > pack_PL;
        shared_ptr<multipacking_gadget<FieldT> > pack_REF;
        shared_ptr<multipacking_gadget<FieldT> > pack_OPS;

        /* variables that will be used for the comparison */
        /* note, that the last two will be implicitely assigned*/
        vector<pb_variable<FieldT>*> data0,
            data0_less, data0_less_or_eq,
            data1,
            data1_less, data1_less_or_eq,
            data2,
            data2_less, data2_less_or_eq,
            data3,
            data3_less, data3_less_or_eq,
            data4,
            data4_less, data4_less_or_eq;

        vector<comparison_gadget<FieldT>*> data0_cgs, data1_cgs, data2_cgs, data3_cgs, data4_cgs;

        /* field's "zero", for reference */
        pb_variable<FieldT> zero;
        pb_variable_array<FieldT> padding_var; /* SHA256 length padding */


        ~zklaim_gadget() {
            /*data0, data0_reference,
              data0_less, data0_less_or_eq,
              data1, data1_reference,
              data1_less, data1_less_or_eq,
              data2, data2_reference,
              data2_less, data2_less_or_eq,
              data3, data3_reference,
              data3_less, data3_less_or_eq,
              data4, data4_reference,
              data4_less, data4_less_or_eq;
              */

            for (auto a: h_rs) {
                delete a;
            }

            for (auto a: h_vars) {
                delete a;
            }

            for (auto a: r_vars) {
                delete a;
            }

            for (auto a: h_r_blocks) {
                delete a;
            }

            for (auto a: ref_vals) {
                delete a;
            }

            for (auto a: ops_vals) {
                delete a;
            }

            for (auto a : data0) {
                delete a;
            }
            for (auto a : data0_less) {
                delete a;
            }
            for (auto a : data0_less_or_eq) {
                delete a;
            }

            for (auto a : data1) {
                delete a;
            }
            for (auto a : data1_less) {
                delete a;
            }
            for (auto a : data1_less_or_eq) {
                delete a;
            }

            for (auto a : data2) {
                delete a;
            }
            for (auto a : data2_less) {
                delete a;
            }
            for (auto a : data2_less_or_eq) {
                delete a;
            }

            for (auto a : data3) {
                delete a;
            }
            for (auto a : data3_less) {
                delete a;
            }
            for (auto a : data3_less_or_eq) {
                delete a;
            }


            for (auto a : data4) {
                delete a;
            }
            for (auto a : data4_less) {
                delete a;
            }
            for (auto a : data4_less_or_eq) {
                delete a;
            }


            data0.clear();
            data0_less.clear();
            data0_less_or_eq.clear();

            data1.clear();
            data1_less.clear();
            data1_less_or_eq.clear();

            data1.clear();
            data1_less.clear();
            data1_less_or_eq.clear();

            data2.clear();
            data2_less.clear();
            data2_less_or_eq.clear();

            data3.clear();
            data3_less.clear();
            data3_less_or_eq.clear();

            data4.clear();
            data4_less.clear();
            data4_less_or_eq.clear();

            for (auto a : data0_cgs) {
                delete a;
            }

            for (auto a : data1_cgs) {
                delete a;
            }

            for (auto a : data2_cgs) {
                delete a;
            }

            for (auto a : data3_cgs) {
                delete a;
            }

            for (auto a : data4_cgs) {
                delete a;
            }


            data0_cgs.clear();
            data1_cgs.clear();
            data2_cgs.clear();
            data3_cgs.clear();
            data4_cgs.clear();

            h_rs.clear();
            h_vars.clear();
            r_vars.clear();
            h_r_blocks.clear();
            h_rs.clear();

        }

        zklaim_gadget(protoboard<FieldT> &pb, zklaim_ctx *ctx)
            : gadget<FieldT>(pb, "zklaim_gadget")
        {

            zklaim_wrap_payload_ctx *cur = ctx->pl_ctx_head;

            this->num_of_payloads = ctx->num_of_payloads;

            // allocate space for the verifier input according to the num of payloads given
            const size_t input_size_in_bits = sha256_digest_len * ctx->num_of_payloads * 5;

            const size_t input_size_in_field_elements = div_ceil(input_size_in_bits, FieldT::capacity());
            input_as_field_elements.allocate(pb, input_size_in_field_elements, "input_as_field_elements");

            this->pb.set_input_sizes(input_size_in_field_elements);

            zero.allocate(this->pb, FMT(this->annotation_prefix, "zero"));

            /*
             * ALLOCATION AND INITIALIZATION OF COMPARISON GADGET
             */
            // bits that will be significant to the comparison gadgets
            // chosen to be the full size of the variables
            const size_t comp_b = 64;

            cur = ctx->pl_ctx_head;
            while (cur != NULL) {
                data0.push_back(new pb_variable<FieldT>());
                data0.back()->allocate(this->pb, "test");
                data0_less.push_back(new pb_variable<FieldT>());
                data0_less.back()->allocate(this->pb, "test");
                data0_less_or_eq.push_back(new pb_variable<FieldT>());
                data0_less_or_eq.back()->allocate(this->pb, "test");

                data1.push_back(new pb_variable<FieldT>());
                data1.back()->allocate(this->pb, "test");
                data1_less.push_back(new pb_variable<FieldT>());
                data1_less.back()->allocate(this->pb, "test");
                data1_less_or_eq.push_back(new pb_variable<FieldT>());
                data1_less_or_eq.back()->allocate(this->pb, "test");

                data2.push_back(new pb_variable<FieldT>());
                data2.back()->allocate(this->pb, "test");
                data2_less.push_back(new pb_variable<FieldT>());
                data2_less.back()->allocate(this->pb, "test");
                data2_less_or_eq.push_back(new pb_variable<FieldT>());
                data2_less_or_eq.back()->allocate(this->pb, "test");

                data3.push_back(new pb_variable<FieldT>());
                data3.back()->allocate(this->pb, "test");
                data3_less.push_back(new pb_variable<FieldT>());
                data3_less.back()->allocate(this->pb, "test");
                data3_less_or_eq.push_back(new pb_variable<FieldT>());
                data3_less_or_eq.back()->allocate(this->pb, "test");

                data4.push_back(new pb_variable<FieldT>());
                data4.back()->allocate(this->pb, "test");
                data4_less.push_back(new pb_variable<FieldT>());
                data4_less.back()->allocate(this->pb, "test");
                data4_less_or_eq.push_back(new pb_variable<FieldT>());
                data4_less_or_eq.back()->allocate(this->pb, "test");

                cur = cur->next;
            }

            // input variable assignment, for sanity check -> prover does not manipulate values
            // we get from the pre-image of the hash
            plvars.allocate(this->pb, 6 * ctx->num_of_payloads, "input validation");
            refvals.allocate(this->pb, 8 * ctx->num_of_payloads, "input validation");
            opsvals.allocate(this->pb, 64 * ctx->num_of_payloads, "operation values");

            // allocate and init comparison gadget
            // check: data1 >/>= data1_reference

            // SHA256's length padding
            for (size_t i = 0; i < 128; i++) {
                if (sha256_padding[i])
                    padding_var.emplace_back(ONE);
                else
                    padding_var.emplace_back(zero);
            }

            // verifier (and prover) inputs:
            for (size_t i = 0; i<ctx->num_of_payloads; i++) {
                h_vars.push_back(new digest_variable<FieldT>(this->pb, sha256_digest_len, "h"));
                ref_vals.push_back(new digest_variable<FieldT>(this->pb, sha256_digest_len * 2, "h"));
                ops_vals.push_back(new digest_variable<FieldT>(this->pb, sha256_digest_len * 2, "h"));
                input_as_bits.insert(input_as_bits.end(), h_vars.back()->bits.begin(), h_vars.back()->bits.end());
                input_as_bits.insert(input_as_bits.end(), ref_vals.back()->bits.begin(), ref_vals.back()->bits.end());
                input_as_bits.insert(input_as_bits.end(), ops_vals.back()->bits.begin(), ops_vals.back()->bits.end());
            }

            // multipacking
            assert(input_as_bits.size() == input_size_in_bits);
            unpack_inputs.reset(new multipacking_gadget<FieldT>(this->pb,
                        input_as_bits,
                        input_as_field_elements,
                        FieldT::capacity(),
                        FMT(this->annotation_prefix, "unpack_inputs")));

            // prover inputs:
            for (size_t i = 0; i<ctx->num_of_payloads; i++) {
                r_vars.push_back(new digest_variable<FieldT>(this->pb, sha256_digest_len + 2*64, "r"));
                for (int l = 0; l<48; l++) {
                    for (int k=7; k>=0; k--) {
                        PL.insert(PL.end(), r_vars.back()->bits.begin()+k+l*8, r_vars.back()->bits.begin()+k+1+l*8);
                    }
                }
            }

            for (size_t i=0; i<ctx->num_of_payloads; i++) {
                for (int l = 0; l<64; l++) {
                    for (int k=7; k>=0; k--) {
                        REF.insert(REF.end(), ref_vals[i]->bits.begin()+k+l*8, ref_vals[i]->bits.begin()+k+1+l*8);
                    }
                }
            }

            for (size_t i=0; i<ctx->num_of_payloads; i++) {
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

            // h_r_blocks
            // h_rs
            // initialize the block gadget for r1's hash
            for (size_t i = 0; i < ctx->num_of_payloads; i++) {
                h_r_blocks.push_back(new block_variable<FieldT>(this->pb, {
                            r_vars[i]->bits,
                            padding_var
                            }, "h_r1_block"));

                // initialize the hash gadget for r1's hash
                h_rs.push_back(new sha256_compression_function_gadget<FieldT>(this->pb,
                            IV,
                            h_r_blocks[i]->bits,
                            *h_vars[i],
                            "h_r1"));
            }
            for (size_t i=0; i<ctx->num_of_payloads; i++) {
                data0_cgs.push_back(new comparison_gadget<FieldT>(this->pb,
                            comp_b,
                            *data0[i],
                            refvals[0 + i*8],
                            *data0_less[i],
                            *data0_less_or_eq[i],
                            "data 0 cmp gadget"));

                data1_cgs.push_back(new comparison_gadget<FieldT>(this->pb,
                            comp_b,
                            *data1[i],
                            refvals[1 + i*8],
                            *data1_less[i],
                            *data1_less_or_eq[i],
                            "data 1 cmp gadget"));

                data2_cgs.push_back(new comparison_gadget<FieldT>(this->pb,
                            comp_b,
                            *data2[i],
                            refvals[2 + i*8],
                            *data2_less[i],
                            *data2_less_or_eq[i],
                            "data 2 cmp gadget"));

                data3_cgs.push_back(new comparison_gadget<FieldT>(this->pb,
                            comp_b,
                            *data3[i],
                            refvals[3 + i*8],
                            *data3_less[i],
                            *data3_less_or_eq[i],
                            "data 3 cmp gadget"));

                data4_cgs.push_back(new comparison_gadget<FieldT>(this->pb,
                            comp_b,
                            *data4[i],
                            refvals[4 + i*8],
                            *data4_less[i],
                            *data4_less_or_eq[i],
                            "data 4 cmp gadget"));

            }
        }

        void add_cmp_constraint(uint8_t op, pb_variable<FieldT> less, pb_variable<FieldT> less_or_eq) {
            switch (op) {
                case zklaim_less:
                    // <
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, less, 1), "less");
                    break;
                case zklaim_less_or_eq:
                    // <=
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, less_or_eq, 1), "less_or_eq");
                    break;
                case zklaim_eq:
                    // equality
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, less_or_eq, 1), "eq");
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, less, 0), "eq");
                    break;
                case zklaim_greater_or_eq:
                    // >=
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, 1 - less, 1), "zklaim_greater_or_eq");
                    break;
                case zklaim_greater:
                    // >
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, 1 - less_or_eq, 1), "greater");
                    break;
                case zklaim_not_eq:
                    // ineq
                    // we want to be sure that either less or greater is true
                    // (less == 1 || less_or_eq == 0) == 1
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, less + (1 - less_or_eq), 1), "not_eq");
                    break;
                case zklaim_noop:
                    break;
                default:
                    cout << "I guess something went terribly wrong... ;)" << endl;
                    cout << "will add an unsatisfiable constraint for security purposes." << endl;
                    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, 0, 1), "fail :(");
            }
        }

        /**
         * generate R1 Constraint System for the gadget
         */
        void generate_r1cs_constraints()
        {
            // multipacking gadget constraints (for input validation)
            unpack_inputs->generate_r1cs_constraints(true);

            // sanity check
            generate_r1cs_equals_const_constraint<FieldT>(this->pb, zero, FieldT::zero(), "zero");

            for (size_t i=0; i < this->num_of_payloads; i++) {
                r_vars[i]->generate_r1cs_constraints();

                // activate the comparison gadget
                // this is needed such that less and less_or_eq are set
                data0_cgs[i]->generate_r1cs_constraints();
                data1_cgs[i]->generate_r1cs_constraints();
                data2_cgs[i]->generate_r1cs_constraints();
                data3_cgs[i]->generate_r1cs_constraints();
                data4_cgs[i]->generate_r1cs_constraints();

                // enforce the reference value not be changable by the prover
                //this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, *data0_reference[i] - this->data0_refs[i], 0));
                //this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, *data0_reference[i] - this->refvals[0], 0));
                //this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, *data1_reference[i] - this->data1_refs[i], 0), "reference validation #1");
                //this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, *data2_reference[i] - this->data2_refs[i], 0), "reference validation #2");
                //this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, *data3_reference[i] - this->data3_refs[i], 0), "reference validation #3");
                //this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, *data4_reference[i] - this->data4_refs[i], 0), "reference validation #4");

                /*this->pb.add_r1cs_constraint(
                  r1cs_constraint<FieldT>(1,
                  opsvals[0 + 0*8 + i*64] * *data0_less[i]
                  + opsvals[1 + 0*8 + i*64] * data0_less_or_eq[i]
                  + opsvals[2 + 0*8 + i*64] * data0_less_or_eq[i] * (1 - data0_less[i])
                  + opsvals[3 + 0*8 + i*64] * (1 - data0_less[i])
                  + opsvals[4 + 0*8 + i*64] * (1 - data0_less_or_eq[i])
                  + opsvals[5 + 0*8 + i*64] * (data0_less[i] + (1 - data0_less_or_eq[i]))
                  + opsvals[6 + 0*8 + i*64], 1), "zklaim_op");
                  */
                this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(opsvals[0 + 0*8 + i*64], *data0_less[i], opsvals[0 + 0*8 + i*64]), "data0_op_less");
                this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(opsvals[1 + 0*8 + i*64], *data0_less_or_eq[i], opsvals[1 + 0*8 + i*64]), "data0_op_less_or_eq");
                this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(opsvals[2 + 0*8 + i*64], *data0_less_or_eq[i], opsvals[2 + 0*8 + i*64]), "data0_op_eq #1");
                this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(opsvals[2 + 0*8 + i*64], *data0_less[i], 0), "data0_op_eq #2");
                this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(opsvals[3 + 0*8 + i*64], 1 - *data0_less[i], opsvals[3 + 0*8 + i*64]), "data0_op_greater_or_eq");
                this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(opsvals[4 + 0*8 + i*64], 1 - *data0_less_or_eq[i], opsvals[4 + 0*8 + i*64]), "data0_op_greater");
                this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(opsvals[5 + 0*8 + i*64], *data0_less[i] + (1 - *data0_less_or_eq[i]), opsvals[5 + 0*8 + i*64]), "data0_op_not_eq");
                this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(opsvals[6 + 0*8 + i*64], 1, opsvals[6 + 0*8 + i*64]), "data0_op_noop");

                this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(opsvals[0 + 1*8 + i*64], *data1_less[i], opsvals[0 + 1*8 + i*64]), "data1_op_less");
                this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(opsvals[1 + 1*8 + i*64], *data1_less_or_eq[i], opsvals[1 + 1*8 + i*64]), "data1_op_less_or_eq");
                this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(opsvals[2 + 1*8 + i*64], *data1_less_or_eq[i], opsvals[2 + 1*8 + i*64]), "data1_op_eq #1");
                this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(opsvals[2 + 1*8 + i*64], *data1_less[i], 0), "data1_op_eq #2");
                this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(opsvals[3 + 1*8 + i*64], 1 - *data1_less[i], opsvals[3 + 1*8 + i*64]), "data1_op_greater_or_eq");
                this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(opsvals[4 + 1*8 + i*64], 1 - *data1_less_or_eq[i], opsvals[4 + 1*8 + i*64]), "data1_op_greater");
                this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(opsvals[5 + 1*8 + i*64], *data1_less[i] + (1 - *data1_less_or_eq[i]), opsvals[5 + 1*8 + i*64]), "data1_op_not_eq");
                this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(opsvals[6 + 1*8 + i*64], 1, opsvals[6 + 1*8 + i*64]), "data1_op_noop");

                this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(opsvals[0 + 2*8 + i*64], *data2_less[i], opsvals[0 + 2*8 + i*64]), "data2_op_less");
                this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(opsvals[1 + 2*8 + i*64], *data2_less_or_eq[i], opsvals[1 + 2*8 + i*64]), "data2_op_less_or_eq");
                this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(opsvals[2 + 2*8 + i*64], *data2_less_or_eq[i], opsvals[2 + 2*8 + i*64]), "data2_op_eq #1");
                this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(opsvals[2 + 2*8 + i*64], *data2_less[i], 0), "data2_op_eq #2");
                this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(opsvals[3 + 2*8 + i*64], 1 - *data2_less[i], opsvals[3 + 2*8 + i*64]), "data2_op_greater_or_eq");
                this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(opsvals[4 + 2*8 + i*64], 1 - *data2_less_or_eq[i], opsvals[4 + 2*8 + i*64]), "data2_op_greater");
                this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(opsvals[5 + 2*8 + i*64], *data2_less[i] + (1 - *data2_less_or_eq[i]), opsvals[5 + 2*8 + i*64]), "data2_op_not_eq");
                this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(opsvals[6 + 2*8 + i*64], 1, opsvals[6 + 2*8 + i*64]), "data2_op_noop");

                this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(opsvals[0 + 3*8 + i*64], *data3_less[i], opsvals[0 + 3*8 + i*64]), "data3_op_less");
                this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(opsvals[1 + 3*8 + i*64], *data3_less_or_eq[i], opsvals[1 + 3*8 + i*64]), "data3_op_less_or_eq");
                this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(opsvals[2 + 3*8 + i*64], *data3_less_or_eq[i], opsvals[2 + 3*8 + i*64]), "data3_op_eq #1");
                this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(opsvals[2 + 3*8 + i*64], *data3_less[i], 0), "data3_op_eq #2");
                this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(opsvals[3 + 3*8 + i*64], 1 - *data3_less[i], opsvals[3 + 3*8 + i*64]), "data3_op_greater_or_eq");
                this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(opsvals[4 + 3*8 + i*64], 1 - *data3_less_or_eq[i], opsvals[4 + 3*8 + i*64]), "data3_op_greater");
                this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(opsvals[5 + 3*8 + i*64], *data3_less[i] + (1 - *data3_less_or_eq[i]), opsvals[5 + 3*8 + i*64]), "data3_op_not_eq");
                this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(opsvals[6 + 3*8 + i*64], 1, opsvals[6 + 3*8 + i*64]), "data3_op_noop");

                this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(opsvals[0 + 4*8 + i*64], *data4_less[i], opsvals[0 + 4*8 + i*64]), "data4_op_less");
                this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(opsvals[1 + 4*8 + i*64], *data4_less_or_eq[i], opsvals[1 + 4*8 + i*64]), "data4_op_less_or_eq");
                this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(opsvals[2 + 4*8 + i*64], *data4_less_or_eq[i], opsvals[2 + 4*8 + i*64]), "data4_op_eq #1");
                this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(opsvals[2 + 4*8 + i*64], *data4_less[i], 0), "data4_op_eq #2");
                this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(opsvals[3 + 4*8 + i*64], 1 - *data4_less[i], opsvals[3 + 4*8 + i*64]), "data4_op_greater_or_eq");
                this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(opsvals[4 + 4*8 + i*64], 1 - *data4_less_or_eq[i], opsvals[4 + 4*8 + i*64]), "data4_op_greater");
                this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(opsvals[5 + 4*8 + i*64], *data4_less[i] + (1 - *data4_less_or_eq[i]), opsvals[5 + 4*8 + i*64]), "data4_op_not_eq");
                this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(opsvals[6 + 4*8 + i*64], 1, opsvals[6 + 4*8 + i*64]), "data4_op_noop");


                // ensure mutual exclusion
                for (int k=0; k<5; k++) {
                    this->pb.add_r1cs_constraint(
                            r1cs_constraint<FieldT>(1,
                                opsvals[0 + k*8 + i*64]
                                + opsvals[1 + k*8 + i*64]
                                + opsvals[2 + k*8 + i*64]
                                + opsvals[3 + k*8 + i*64]
                                + opsvals[4 + k*8 + i*64]
                                + opsvals[5 + k*8 + i*64]
                                + opsvals[6 + k*8 + i*64], 1), "consistency check");
                }

                // ops don't need to be enforced, as this is explicitely done by the corresponding constraint
                // in the circuit

                // enforce that what we compare is also contained in the input at the
                // right slot
                this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, *data0[i] - plvars[0 + i*6], 0), "input validation #0");
                this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, *data1[i] - plvars[1 + i*6], 0), "input validation #1");
                this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, *data2[i] - plvars[2 + i*6], 0), "input validation #2");
                this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, *data3[i] - plvars[3 + i*6], 0), "input validation #3");
                this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, *data4[i] - plvars[4 + i*6], 0), "input validation #4");

                /*add_cmp_constraint(data0_ops[i], *data0_less[i], *data0_less_or_eq[i]);
                  add_cmp_constraint(data1_ops[i], *data1_less[i], *data1_less_or_eq[i]);
                  add_cmp_constraint(data2_ops[i], *data2_less[i], *data2_less_or_eq[i]);
                  add_cmp_constraint(data3_ops[i], *data3_less[i], *data3_less_or_eq[i]);
                  add_cmp_constraint(data4_ops[i], *data4_less[i], *data4_less_or_eq[i]);
                  */
                // constraint to ensure the hashes validate.
                h_rs[i]->generate_r1cs_constraints();
            }
        }

        /**
         * generate witnesses for the constraint system of this gadget
         * need to provide assignment to necessary variables
         */
        void generate_r1cs_witness(zklaim_ctx *ctx)
        {
            // set pb zeoro to field zero
            this->pb.val(zero) = FieldT::zero();
            // fill pre-image with witnessed data
            zklaim_wrap_payload_ctx *cur = ctx->pl_ctx_head;
            int i = 0;
            bit_vector r, refs_vec, ops_vec;
            unsigned char ref_in[512];
            unsigned char ops[512];
            while (cur != NULL) {
                memset(ref_in, 0, sizeof(ref_in));
                memcpy(ref_in, &cur->pl.data_ref[0], 8);
                memcpy(ref_in+8, &cur->pl.data_ref[1], 8);
                memcpy(ref_in+16, &cur->pl.data_ref[2], 8);
                memcpy(ref_in+24, &cur->pl.data_ref[3], 8);
                memcpy(ref_in+32, &cur->pl.data_ref[4], 8);

                memset(ops, 0, 512);
                set_zklaim_ops(ops, cur->pl.data_op[0]);
                set_zklaim_ops(ops+8, cur->pl.data_op[1]);
                set_zklaim_ops(ops+16, cur->pl.data_op[2]);
                set_zklaim_ops(ops+24, cur->pl.data_op[3]);
                set_zklaim_ops(ops+32, cur->pl.data_op[4]);
                //memcpy(ops, &cur->pl.data0_op, sizeof(cur->pl.data0_op));
                //memcpy(ops+8, &cur->pl.data1_op, sizeof(cur->pl.data0_op));
                //memcpy(ops+16, &cur->pl.data1_op, sizeof(cur->pl.data0_op));
                //memcpy(ops+24, &cur->pl.data1_op, sizeof(cur->pl.data0_op));
                //memcpy(ops+32, &cur->pl.data1_op, sizeof(cur->pl.data0_op));

                refs_vec = memtobv(ref_in, 512);
                ops_vec = memtobv(ops, 512);
                r = memtobv(cur->pl.pre, 384);
                r_vars[i]->bits.fill_with_bits(this->pb, r);
                uint64_t recvd_data0 = extractFromBV(r, 0),
                         recvd_data1 = extractFromBV(r, 1),
                         recvd_data2 = extractFromBV(r, 2),
                         recvd_data3 = extractFromBV(r, 3),
                         recvd_data4 = extractFromBV(r, 4);
                // prover sets the values contained in her credential
                // this is enforced by the circuit
                this->pb.val(*data0[i]) = FieldT(recvd_data0);
                this->pb.val(*data1[i]) = FieldT(recvd_data1);
                this->pb.val(*data2[i]) = FieldT(recvd_data2);
                this->pb.val(*data3[i]) = FieldT(recvd_data3);
                this->pb.val(*data4[i]) = FieldT(recvd_data4);

                //data0_cgs[i]->generate_r1cs_witness();
                //data1_cgs[i]->generate_r1cs_witness();
                //data2_cgs[i]->generate_r1cs_witness();
                //data3_cgs[i]->generate_r1cs_witness();
                //data4_cgs[i]->generate_r1cs_witness();

                // generate witness for other gadgets in use (hash gadget, etc.)
                h_rs[i]->generate_r1cs_witness();
                h_vars[i]->bits.fill_with_bits(this->pb, memtobv(cur->pl.hash, 256));
                ref_vals[i]->bits.fill_with_bits(this->pb, refs_vec);
                ops_vals[i]->bits.fill_with_bits(this->pb, ops_vec);
                i += 1;
                cur = cur->next;
            }

            unpack_inputs->generate_r1cs_witness_from_bits();
            pack_REF->generate_r1cs_witness_from_bits();
            pack_OPS->generate_r1cs_witness_from_bits();
            cout << endl << opsvals.get_vals(this->pb) << endl;

            for (size_t i=0; i<ctx->num_of_payloads; i++) {
                data0_cgs[i]->generate_r1cs_witness();
                data1_cgs[i]->generate_r1cs_witness();
                data2_cgs[i]->generate_r1cs_witness();
                data3_cgs[i]->generate_r1cs_witness();
                data4_cgs[i]->generate_r1cs_witness();
            }

            pack_PL->generate_r1cs_witness_from_bits();
            cout << endl << plvars.get_vals(this->pb) << endl;

        }
};


