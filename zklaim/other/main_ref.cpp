#include <iostream>
#include <assert.h>

#include <libsnark/gadgetlib2/gadget.hpp>
#include <libsnark/gadgetlib2/integration.hpp>
#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>
#include <libff/common/default_types/ec_pp.hpp>

using namespace libsnark;

int main() {
    typedef libff::Fr<libff::default_ec_pp> FieldT;

    gadgetlib2::initPublicParamsFromDefaultPp();
    auto pb = gadgetlib2::Protoboard::create(gadgetlib2::R1P);
    size_t size =  100;
    const gadgetlib2::PackedWord lhs;
    const gadgetlib2::PackedWord rhs;
    const gadgetlib2::FlagVariable less;
    const gadgetlib2::FlagVariable lessOrEqual;
    auto g = gadgetlib2::Comparison_Gadget::create(pb, 3, lhs, rhs, less, lessOrEqual);
    g->generateConstraints();
    pb->val(lhs) = 5;
    pb->val(rhs) = 5;
    g->generateWitness();
    assert(pb->isSatisfied());
    assert(pb->val(less) == 0);
    assert(pb->val(lessOrEqual) == 1);
    // translate constraint system to libsnark format.
    r1cs_constraint_system<FieldT> cs = get_constraint_system_from_gadgetlib2(*pb);
    // translate full variable assignment to libsnark format
    const r1cs_variable_assignment<FieldT> full_assignment = get_variable_assignment_from_gadgetlib2(*pb);
    // extract primary and auxiliary input
    const r1cs_primary_input<FieldT> primary_input(full_assignment.begin(), full_assignment.begin() + cs.num_inputs());
    const r1cs_auxiliary_input<FieldT> auxiliary_input(full_assignment.begin() + cs.num_inputs(), full_assignment.end());

    assert(cs.is_satisfied(primary_input, auxiliary_input));
    assert(0); // FAILS
	printf("%d\n", pb->isSatisfied());
}
