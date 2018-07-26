Overview & PoC
~~~~~~~~~~~~~~
Current Mapping depicted within PoC:
====================================
We have a credential, that contains a single payload vector which in turn contains AGE, SALARY, a dummy variable and the SALT.
Please note, that the description below is true for the PoC with code tagged as zklaim_POC.

Cred
====

.. code-block:: c

    ===================
    h = PL1(see above)
    -------------------
    Signature
    ===================


We prove the following
======================
- we know a `x := age | salary | dummy | SALT` s.t. `SHA256(x) = h`
- age >= 18
- salary > 50000

Get Up and Running
~~~~~~~~~~~~~~~~~~
- clone repository / fetch & pull newest changes
- checkout branch snark (`git checkout snark`)
- create build dir (`mkdir build`)
- switch to build dir (`cd build`)
- generate build config (`cmake ..`)
- compile (`make -j 4`)
- generate ECC private key `openssl ecparam -name secp256k1 -genkey -noout -out src/ca_ecc_key.pem`
- generate ECC public key `openssl ec -in src/ca_ecc_key.pem -pubout -out src/ca_ecc_key_pub.pem`
- run (`src/main`)

The most important result that is displayed is: `proof valid: yes`, if '**yes**' is displayed, this means that the proof is both formally valid and the prover selected inputs that satisfied all constraints. **no** either means, that the proof is not formally valid or the constraint system is not satisfied.

Code Summary
~~~~~~~~~~~~
main.cpp
========
contains the proof of concept code, a credential is built and signed/verified and  a proof is generated and validated.

the attributes are manually set and copied over to a dedicated memory region, then a bit_vector (**`typedef std::vector<bool>`!**) is built for interfacing with libsnark.

snark.hpp
=========
contains higher level interfaces for using **high-level** gadgets in libsnark like generate_keys(), prove() and verify(). this is, where users of zklaim will possibly adapt gadgets to their needs (pending design decisions)

gadget.hpp
==========
contains (an ugly and monolithic) demonstrary zklaim gadget. every gadget that is defined as a class needs to prove a constructor as well as **generate_r1cs_constraints()** to setup the constraint system and **generate_r1cs_witness** to fill in the values.

.. code-block:: C++

    // r1cs_constraint(A, B, C) adds a constraint s.t. it needs to hold: A*B = C
    // this constraint is needed to enforce the reference we want to compare for with the given circuit
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, age_reference-18, 0));

    // age represents a variable filled in by the prover, plvars contains the attributes from the hash payload
    // note: in the future, we can also directly assign plvars to age, s.t. the prover does not need to take an
    // extra step
    // this is needed s.t. prover don't cheat and use attribute values from the (correct) credential position
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, age - plvars[0], 0));

    // the comparison gadgets set the less and less_or_eq variables according to input assignments
    // this constraint enforces that the cred. input >= age_reference
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, age_less_or_eq, 1));

Contents
~~~~~~~~
- gadget.hpp: gadgets zklaim provides and uses
- lamport.{h, c}: the lamport signature scheme
- hashio.hpp: a class for hash operations and representing digests
- main.cpp: main test program logic
- merkle.{h, c}: merkle tree operations and algorithm
- snark.hpp: higher-level libsnark operations, generate keypair/proof/verify
- zklaim_cred.hpp: definitions of a zklaim credential
- tests/: directory for unit tests
- other/: files currently not in use
