/**
 * taken from https://github.com/ebfull/lightning_circuit/ (under MIT license)
 * adapted
 */

#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>
#include <libff/algebra/fields/field_utils.hpp>

const size_t sha256_digest_len = 256;


/*
   computed by:
   unsigned long long bitlen = 256;
   unsigned char padding[32] = {0x80, 0x00, 0x00, 0x00, // 24 bytes of padding
   0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00,
   bitlen >> 56, bitlen >> 48, bitlen >> 40, bitlen >> 32, // message length
   bitlen >> 24, bitlen >> 16, bitlen >> 8, bitlen
   };
   std::vector<bool> padding_bv(256);
   convertBytesToVector(padding, padding_bv);
   printVector(padding_bv);
   */

/* this is needed as a 2-to-1-compression sha256-gadget is used, thus we pad our input to 512 */
bool sha256_padding[256] = {1,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,1, 0,0,0,0,0,0,0,0};

bool debug = false;

uint64_t extractFromBV(const libff::bit_vector &r, uint8_t slot_offset) {
    uint64_t var = 0;

    if (slot_offset > 2) {
        printf("current construction only allows 3 elements in a zklaim payload!\n");
        printf("returning -1 dummy value");
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

using namespace libsnark;
using namespace libff;
using namespace std;

template<typename FieldT>
class l_gadget : public gadget<FieldT> {
    public:
        pb_variable_array<FieldT> input_as_field_elements; /* R1CS input */
        pb_variable_array<FieldT> input_as_bits; /* unpacked R1CS input */
        pb_variable_array<FieldT> plvars;
        pb_variable_array<FieldT> PL;

        shared_ptr<multipacking_gadget<FieldT> > unpack_inputs; /* multipacking gadget */

        shared_ptr<digest_variable<FieldT>> h1_var; /* H(R1) */
        shared_ptr<digest_variable<FieldT>> r1_var; /* R1 */

        shared_ptr<block_variable<FieldT>> h_r1_block; /* 512 bit block that contains r1 + padding */
        shared_ptr<sha256_compression_function_gadget<FieldT>> h_r1; /* hashing gadget for r1 */
        shared_ptr<multipacking_gadget<FieldT> > pack_PL;

        /* represent values we want to perform comparison on */
        shared_ptr<pb_linear_combination<FieldT>> timestamp, current;

        /* variables that will be used for the comparison */
        /* note, that the last two will be implicitely assigned*/
        pb_variable<FieldT> age, age_reference, age_less, age_less_or_eq,
            salary, salary_reference, salary_less, salary_less_or_eq;
        shared_ptr<comparison_gadget<FieldT>> age_cg, salary_cg;

        /* field's "zero", for reference */
        pb_variable<FieldT> zero;
        pb_variable_array<FieldT> padding_var; /* SHA256 length padding */


        l_gadget(protoboard<FieldT> &pb) : gadget<FieldT>(pb, "l_gadget")
    {
        // Allocate space for the verifier input.
        const size_t input_size_in_bits = sha256_digest_len * 1;

        // we use a "multipacking" technique which allows us to constrain
        // the input bits in as few field elements as possible.
        const size_t input_size_in_field_elements = div_ceil(input_size_in_bits, FieldT::capacity());
        input_as_field_elements.allocate(pb, input_size_in_field_elements, "input_as_field_elements");
        this->pb.set_input_sizes(input_size_in_field_elements);

        zero.allocate(this->pb, FMT(this->annotation_prefix, "zero"));

        /*
         * ALLOCATION AND INITIALIZATION OF COMPARISON GADGET
         */
        const size_t comp_b = 64;
        age_reference.allocate(this->pb, "reference value to compare for");
        this->pb.val(age_reference) = FieldT(18);
        age.allocate(this->pb, "value from payload");

        age_less.allocate(this->pb, "less");
        age_less_or_eq.allocate(this->pb, "less_or_eq");

        salary_less.allocate(this->pb, "less");
        salary_less_or_eq.allocate(this->pb, "less_or_eq");

        salary_reference.allocate(this->pb, "reference value to compare for");
        this->pb.val(salary_reference) = FieldT(50000);
        salary.allocate(this->pb, "value from payload");


        plvars.allocate(this->pb, 4, "input validation");

        // allocate and init comparison gadget
        age_cg.reset(new comparison_gadget<FieldT>(this->pb,
                    comp_b,
                    age_reference,
                    age,
                    age_less,
                    age_less_or_eq,
                    FMT(this->annotation_prefix, "comparison gadget")));

        salary_cg.reset(new comparison_gadget<FieldT>(this->pb,
                    comp_b,
                    salary_reference,
                    salary,
                    salary_less,
                    salary_less_or_eq,
                    FMT(this->annotation_prefix, "comparison gadget")));

        // SHA256's length padding
        for (size_t i = 0; i < 256; i++) {
            if (sha256_padding[i])
                padding_var.emplace_back(ONE);
            else
                padding_var.emplace_back(zero);
        }

        // verifier (and prover) inputs:
        h1_var.reset(new digest_variable<FieldT>(this->pb, sha256_digest_len, "h1"));

        input_as_bits.insert(input_as_bits.end(), h1_var->bits.begin(), h1_var->bits.end());

        // multipacking
        assert(input_as_bits.size() == input_size_in_bits);
        unpack_inputs.reset(new multipacking_gadget<FieldT>(this->pb,
                    input_as_bits,
                    input_as_field_elements,
                    FieldT::capacity(),
                    FMT(this->annotation_prefix, " unpack_inputs")));

        // prover inputs:
        r1_var.reset(new digest_variable<FieldT>(this->pb, sha256_digest_len, "r1"));

        for (int i = 0; i<32; i++) {
            for (int k=7; k>=0; k--) {
                PL.insert(PL.end(), r1_var->bits.begin()+k+i*8, r1_var->bits.begin()+k+1+i*8);
            }
        }

        //PL.insert(PL.end(), r1_var->bits.begin()+8, r1_var->bits.end());
        input_as_bits.insert(input_as_bits.end(), r1_var->bits.begin(), r1_var->bits.end());
        // IV for SHA256
        pb_linear_combination_array<FieldT> IV = SHA256_default_IV(pb);

        pack_PL.reset(new multipacking_gadget<FieldT>(pb, PL, plvars, 64, FMT(this->annotation_prefix, " pack_alpha")));

        // initialize the block gadget for r1's hash
        h_r1_block.reset(new block_variable<FieldT>(this->pb, {
                    r1_var->bits,
                    padding_var
                    }, "h_r1_block"));

        // initialize the hash gadget for r1's hash
        h_r1.reset(new sha256_compression_function_gadget<FieldT>(this->pb,
                    IV,
                    h_r1_block->bits,
                    *h1_var,
                    "h_r1"));

    }
        /**
         * generate R1 Constraint System for the gadget
         */
        void generate_r1cs_constraints()
        {
            // Multipacking constraints (for input validation)
            unpack_inputs->generate_r1cs_constraints(true);

            // Ensure bitness of the digests. Bitness of the inputs
            // is established by `unpack_inputs->generate_r1cs_constraints(true)`
            r1_var->generate_r1cs_constraints();

            // sanity check
            generate_r1cs_equals_const_constraint<FieldT>(this->pb, zero, FieldT::zero(), "zero");

            // activates the comparison gadget
            // this is needed such that less and less_or_eq are set
            age_cg.get()->generate_r1cs_constraints();

            salary_cg.get()->generate_r1cs_constraints();

            // enforce the reference value not be changable by the prover
            this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, age_reference-18, 0));
            this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, salary_reference-50000, 0));

            // enforce that what we compare is also contained in the input at the
            // right slot
            this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, age - plvars[0], 0));
            this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, salary - plvars[1], 0));

            // value should be less!
            this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, age_less_or_eq, 1));
            this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, salary_less, 1));

            // constraint to ensure the hashes validate.
            h_r1->generate_r1cs_constraints();
        }

        /**
         * generate witnesses for the constraint system of this gadget
         * need to provide assignment to necessary variables
         */
        void generate_r1cs_witness(const bit_vector &h1, const bit_vector &r1)
        {
            // fill pre-image with witnessed data
            r1_var->bits.fill_with_bits(this->pb, r1);

            // dirty hack: copy bitvector back to mem region
            uint64_t cred_age = extractFromBV(r1, 0),
                     cred_salary = extractFromBV(r1, 1);
            //cout << endl << typeid(r1_var.get()->bits.get_bits(this->pb)[0]).name() << endl;
            //cout << cred->get_bits();

            //cout << endl << cred_salary << endl << endl;
            //_exit(1);
            // Set the zero pb_variable to zero
            this->pb.val(zero) = FieldT::zero();
            // prover sets the age contained in her credential
            // this is enforced by the circuit
            this->pb.val(age) = FieldT(cred_age);
            this->pb.val(salary) = FieldT(cred_salary);
            this->pb.val(salary_reference) = FieldT(50000);
            this->pb.val(age_reference) = FieldT(18);

            age_cg.get()->generate_r1cs_witness();
            salary_cg.get()->generate_r1cs_witness();

            //printf("less: %d\n", this->pb.val(less).as_ulong());

            // generate witness for other gadgets in use (hash gadget, etc.)
            h_r1->generate_r1cs_witness();
            unpack_inputs->generate_r1cs_witness_from_bits();

            pack_PL->generate_r1cs_witness_from_bits();
            h1_var->bits.fill_with_bits(this->pb, h1);
            cout << endl << plvars.get_vals(this->pb) << endl;
            cout << input_as_field_elements.get_vals(this->pb) << endl;
        }
};

/**
 *  this is needed as to map the verifiers input to a single primary input for the verification algorithm
 *  this also has to be adapted for possibly changed inputs the verifier might have
 */
    template<typename FieldT>
r1cs_primary_input<FieldT> l_input_map(const bit_vector &h1)
{
    // construct the multipacked field points which encode
    // the verifier's knowledge. This is the "dual" of the
    // multipacking gadget logic in the constructor.
    // TODO: get rid of assert as it is not working anyway
    assert(h1.size() == sha256_digest_len);

    bit_vector input_as_bits;
    input_as_bits.insert(input_as_bits.end(), h1.begin(), h1.end());

    vector<FieldT> input_as_field_elements = pack_bit_vector_into_field_element_vector<FieldT>(input_as_bits);
    return input_as_field_elements;
}
