#include <libff/common/default_types/ec_pp.hpp>
#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>
#include <libff/algebra/fields/field_utils.hpp>

#include <libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp>
#include <string.h>

using namespace libsnark;

/**
 * target: prove, that we have pre-image R1 to some hash H(R1)
 * H(R1) Hash
 * R1 pre-image
 */
	template<typename FieldT>
void test_two_to_one()
{
	protoboard<FieldT> pb;
	bool sha256_padding[256] =
	{1,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
		0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
		0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
		0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
		0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
		0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
		0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
		0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,1, 0,0,0,0,0,0,0,0};

	pb_variable_array<FieldT> input_as_field_elements; /* R1CS input */
	pb_variable_array<FieldT> input_as_bits; /* unpacked R1CS input */
	std::shared_ptr<multipacking_gadget<FieldT> > unpack_inputs; /* multipacking gadget */

	std::shared_ptr<digest_variable<FieldT>> h1_var; /* H(R1) */
	std::shared_ptr<digest_variable<FieldT>> r1_var; /* R1 */

	const size_t input_size_in_bits = 256 * 3;
	const size_t input_size_in_field_elements = libff::div_ceil(input_size_in_bits, FieldT::capacity());
	input_as_field_elements.allocate(pb, input_size_in_field_elements, "input_as_field_elements");
	pb.set_input_sizes(input_size_in_field_elements);

	pb_variable<FieldT> zero;
	zero.allocate(pb, "zero");
	pb_variable_array<FieldT> padding_var;

	for (size_t i = 0; i < 256; i++) {
		if (sha256_padding[i])
			padding_var.emplace_back(ONE);
		else
			padding_var.emplace_back(zero);

	}

	std::shared_ptr<block_variable<FieldT>> h_r1_block;
	std::shared_ptr<sha256_compression_function_gadget<FieldT>> h_r1;

	h1_var.reset(new digest_variable<FieldT>(pb, 256, "h1"));
	r1_var.reset(new digest_variable<FieldT>(pb, 256, "r1"));

	pb_linear_combination_array<FieldT> IV = SHA256_default_IV(pb);

	h_r1_block.reset(new block_variable<FieldT>(pb, {
				r1_var->bits,
				padding_var
				}, "h_r1_block"));

	input_as_bits.insert(input_as_bits.end(), h1_var->bits.begin(), h1_var->bits.end());
	assert(input_as_bits.size() == input_size_in_bits);
	unpack_inputs.reset(new multipacking_gadget<FieldT>(pb, input_as_bits, input_as_field_elements, FieldT::capacity(), " unpack_inputs"));
	r1_var.reset(new digest_variable<FieldT>(pb, 256, "r1"));

	h_r1.reset(new sha256_compression_function_gadget<FieldT>(pb,
				IV,
				h_r1_block->bits,
				*h1_var,
				"h_r1"));

	unpack_inputs->generate_r1cs_constraints(true);
	r1_var->generate_r1cs_constraints();
	generate_r1cs_equals_const_constraint<FieldT>(pb, zero, FieldT::zero(), "zero");
	h_r1->generate_r1cs_constraints();

	// TEST SECTION
	// with concrete values
	std::vector<bool> r1_bv(256);
	std::vector<bool> h1_bv(256);
	r1_bv = libff::int_list_to_bits({180, 34, 250, 166, 200, 177, 240, 137, 204, 219, 178, 17, 34, 14, 66, 65, 203, 6, 191, 16, 141, 210, 73, 136, 65, 136, 152, 60, 117, 24, 101, 18}, 8);
	h1_bv = libff::int_list_to_bits({169, 231, 96, 189, 221, 234, 240, 85, 213, 187, 236, 114, 100, 185, 130, 86, 231, 29, 123, 196, 57, 225, 159, 216, 34, 190, 123, 97, 14, 57, 180, 120}, 8);

	r1_var->bits.fill_with_bits(pb, r1_bv);
	pb.val(zero) = FieldT::zero();
	h_r1->generate_r1cs_witness();
	unpack_inputs->generate_r1cs_witness_from_bits();
	h1_var->bits.fill_with_bits(pb, h1_bv);
	//h_r1->generate_r1cs_witness();

	printf("===============================\n");
	printf("====== is satisfied: %s ======\n", pb.is_satisfied()? "yes" : "no");
	printf("===============================\n");
}

int main(void)
{
	libff::default_ec_pp::init_public_params();
	test_two_to_one<libff::Fr<libff::default_ec_pp>>();
}
