#include <libff/common/default_types/ec_pp.hpp>
#include <libsnark/gadgetlib2/adapters.hpp>
#include <libsnark/common/default_types/r1cs_gg_ppzksnark_pp.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>
#include <libsnark/gadgetlib2/examples/simple_example.hpp>
#include <libsnark/gadgetlib2/gadget.hpp>
#include <libsnark/gadgetlib2/integration.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/examples/run_r1cs_ppzksnark.hpp>
#include <iostream>
#include <fstream>

using namespace libsnark;
using namespace gadgetlib2;

typedef libff::Fr<libff::default_ec_pp> FieldT;
typedef default_r1cs_gg_ppzksnark_pp ppT;

bool exportParams = false;

int main () {
    initPublicParamsFromDefaultPp();

    GadgetLibAdapter::resetVariableIndex();

    auto pb = Protoboard::create(R1P);

    const VariableArray A(10, "A");
    const VariableArray B(10, "B");
    const Variable result("result");

    auto g = OR_Gadget::create(pb, A, result);

    for(int i = 0; i < 10; i++) {
        pb->val(A[i]) = std::rand() % 2;
        printf("A[%d]: %lu\n", i, pb->val(A[i]).asLong());
        pb->val(B[i]) = std::rand() % 2;
    }

    g->generateWitness();

    pb->addUnaryConstraint(1 - result, "1 - result == 0");

    printf("is satisfied: %u\n", pb->isSatisfied());
    printf("result of gadget op: %lu\n", pb->val(result).asLong());


    r1cs_constraint_system<FieldT> cs = get_constraint_system_from_gadgetlib2(*pb);

    // translate full variable assignment to libsnark format
    const r1cs_variable_assignment<FieldT> full_assignment = get_variable_assignment_from_gadgetlib2(*pb);

    // extract primary and auxiliary input
    const r1cs_primary_input<FieldT> primary_input(full_assignment.begin(), full_assignment.begin() + cs.num_inputs());
    const r1cs_auxiliary_input<FieldT> auxiliary_input(full_assignment.begin() + cs.num_inputs(), full_assignment.end());

    printf("Constraint system valid: %d\n", cs.is_valid());
    printf("Constraint system satisfied: %d\n", cs.is_satisfied(primary_input, auxiliary_input));

    r1cs_gg_ppzksnark_keypair<default_r1cs_gg_ppzksnark_pp> keypair = r1cs_gg_ppzksnark_generator<default_r1cs_gg_ppzksnark_pp>(cs);

    r1cs_gg_ppzksnark_processed_verification_key<ppT> pvk = r1cs_gg_ppzksnark_verifier_process_vk<ppT>(keypair.vk);

    r1cs_gg_ppzksnark_proof<ppT> proof = r1cs_gg_ppzksnark_prover<ppT>(keypair.pk, primary_input, auxiliary_input);

    const bool ans = r1cs_gg_ppzksnark_verifier_strong_IC<ppT>(keypair.vk, primary_input, proof);
    printf("* The verification result is: %s\n", (ans ? "PASS" : "FAIL"));

    if (exportParams) {
        std::ofstream myfile;
        myfile.open("proof");
        myfile << proof;
        myfile.close();

        myfile.open("vk");
        myfile << keypair.vk;
        myfile.close();

        myfile.open("pk");
        myfile << keypair.pk;
        myfile.close();

        myfile.open("primary_in");
        myfile << primary_input;
        myfile.close();
    }

    const bool ans2 = r1cs_gg_ppzksnark_online_verifier_strong_IC<ppT>(pvk, primary_input, proof);
    printf("* The verification result 1 is: %s\n", (ans ? "PASS" : "FAIL"));
    printf("* The verification result 2 is: %s\n", (ans2 ? "PASS" : "FAIL"));

    return 0;
}
