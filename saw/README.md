# SAW Proofs

SAW Proofs on Cryptol Specification of AWS Encryption C SDK Code

## Dependencies 

You will need a version of SAW (https://saw.galois.com/). 

The official releases are quite old at this point. 
The simplest method is to use a nightly (https://saw.galois.com/builds/nightly/). All proofs I have currently run are 
performed using the saw-0.2-2018-09-05-MacOSX-6 nightly build. 
It is also possible to build SAW from source. 

## Solvers

SAW has several automated tactics. The ProofScript values abc and z3 select the ABC and Z3 theorem provers,
respectively, and are typically good choices. In addition to these, the boolector, cvc4, mathsat, and yices provers 
are available. These do not need to be installed and are internal. 

SAW supports more generic interfaces to other arbitrary theorem provers supporting specific interfaces, but I don't 
think this will be necessary. 

## Code Structure 

There are five .cry files and one .saw file. 

    type_def.cry contains the type declarations for the Cryptol types as well as constants. 

    helper_functions.cry contains helper functions to reduce code bloat due to common subroutines. 

    transition_functions.cry contains the Cryptol specification of the state machine transition functions. 

    state_machine.cry contains the Cryptol specification of the state machine, conditions for the process loop to 
    continue, and buffer update checks. 

    proofs.cry contains a set of progress properties verifiably with a SAT-solver. 

    state_machine.saw contains the harness from SAW to run the proofs specified in proofs.cry 

## How to Run 

To run state_machine.saw: 
    
    $PATH_TO_SAW_DIR/bin/saw state_machine.saw

## Equivalence Proof 

SAW can also be leveraged to prove the equivalence between the Cryptol specification and the underlying C code. These 
proofs are currently a work in progress but there will be a seperate pull request containing them. The equivalence
proofs can be used to determine when the Cryptol specification falls out of sync with the C implementation and needs 
to be updated. 





