// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

struct ConsensusState {
    uint256 height;
    uint256 weight;
    uint256 target;
    uint64 period_started_at;
    Header header;
    uint256 hash;
}

struct Header {
    uint32 version;
    uint256 prev_hash;
    uint256 merkle_root;
    uint32 time;
    uint32 nbits;
    uint32 nonce;
}

struct Output {
    ConsensusState old_state;
    ConsensusState new_state;
}

contract IFactRegistry {
    /*
      Returns true if the given fact was previously registered in the contract.
    */
    function isValid(bytes32 fact) external view returns (bool);
}

/*
  ZKPOW maintains the state of a Bitcoin network utilizing STARK proofs to avoid
  processing all block headers.
*/
contract ZKPOW {
    // The current state of the tracked network
    ConsensusState initialState;
    ConsensusState currentState;

    // The Cairo program hash.
    uint256 cairoProgramHash_;

    // The Cairo verifier.
    IFactRegistry cairoVerifier_;

    // Initializes the contract state.
    constructor(
        ConsensusState initialState,
        uint256 cairoProgramHash,
        address cairoVerifier
    ) public {
        initialState = initialState;
        currentState = initialState;
        cairoProgramHash_ = cairoProgramHash;
        cairoVerifier_ = IFactRegistry(cairoVerifier);
    }

    // calculateOutputFact generates the fact for our program and the given
    // program output.
    function calculateOutputFact(uint256[] memory programOutput) view {
        bytes32 outputHash = keccak256(abi.encodePacked(programOutput));
        return keccak256(abi.encodePacked(cairoProgramHash_, outputHash));
    }

    // outputFactIsValid checks if the given program output has been validated
    // for our program.
    function outputFactIsValid(uint256[] memory programOutput) view {
        bytes32 fact = calculateOutputFact(programOutput);
        return cairoVerifier_.isValid(fact);
    }

    // startingHashFromOutput parses the starting state hash from a program
    // output.
    function startingHashFromOutput(uint256[] memory programOutput) view {
        uint256 starting_hash;
        return starting_hash;
    }

    // newStateFromOutput parses the generated state from the program output.
    function newStateFromOutput(uint256[] memory programOutput) view {
        ConsensusState new_state;
        return new_state;
    }

    function outputIsValidAndExtends(uint256[] memory programOutput) view {
        ConsensusState new_state;
        return new_state;
    }

    // updateState sets the currentState to be equal to the given program
    // output's resultant state, if and only if it's valid.
    function updateState(uint256[] memory programOutput) public {
        // Ensure the given program output has been validated
        require(outputFactIsValid(programOutput), "MISSING_CAIRO_PROOF");

        // Ensure the given program output is starting from our current state
        uint256 startingHash = startingHashFromOutput(programOutput);
        require(startingHash == currentState.hash, "INCORRECT_STARTING_STATE");

        // Ensure the new state is heavier than the current state
        ConsensusState newState = newStateFromOutput(programOutput);
        require(newState.weight > currentState.weight, "NOT_ENOUGH_WEIGHT");

        // Update system state.
        currentState = newState;
    }
}
