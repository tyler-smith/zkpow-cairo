// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

 struct CircuitState {
    bytes32 genesisHash;
    uint64 height;
    uint256 weight;
    uint256 target;
    uint64 periodStartedAt;
    Header header;
    bytes32 hash;
}

struct Header {
    uint32 version;
    bytes32 prevHash;
    bytes32 merkleRoot;
    uint32 time;
    uint32 nbits;
    uint32 nonce;
}

interface IFactRegistry {
    // Returns true if the given fact was previously registered in the contract.
    function isValid(bytes32 fact) external view returns (bool);
}

/*
  ZKPOW maintains the state of a Bitcoin network utilizing STARK proofs to avoid
  processing all block headers.
*/
contract ZKPOW {
    // The current state of the network being tracked
    CircuitState public currentState;

    // The Cairo program hash.
    uint256 public immutable cairoProgramHash;

    // The Cairo verifier.
    IFactRegistry public immutable cairoVerifier;

    // Initializes the contract state.
    constructor(
        CircuitState memory _initialState,
        uint256 _cairoProgramHash,
        IFactRegistry _cairoVerifier
    ) {
        currentState = _initialState;
        cairoProgramHash = _cairoProgramHash;
        cairoVerifier = IFactRegistry(_cairoVerifier);
    }

    //
    // Network state accessors
    //

    function genesisHash() public view returns (bytes32) {
        return currentState.genesisHash;
    }

    function hash() public view returns (bytes32) {
        return currentState.hash;
    }

    function height() public view returns (uint64) {
        return currentState.height;
    }

    function weight() public view returns (uint256) {
        return currentState.weight;
    }

    function target() public view returns (uint256) {
        return currentState.target;
    }

    function periodStartedAt() public view returns (uint64) {
        return currentState.periodStartedAt;
    }

    function lastHeader() public view returns (Header memory) {
        return currentState.header;
    }

    function getCurrentState() public view returns (CircuitState memory) {
        return currentState;
    }

    // calculateFact generates the fact for our program and the given output.
    function calculateFact(uint256[] memory programOutput) public view returns (bytes32) {
        bytes32 outputHash = keccak256(abi.encodePacked(programOutput));
        return keccak256(abi.encodePacked(cairoProgramHash, outputHash));
    }

    // outputFactIsValid checks if the given program output has been validated
    // for our program.
    function outputFactIsValid(uint256[] calldata programOutput) public view returns (bool) {
        bytes32 fact = calculateFact(programOutput);
        return cairoVerifier.isValid(fact);
    }

    // updateState sets the currentState to be equal to the given program
    // output's resultant state, if and only if it's valid.
    function updateState(uint256[] calldata programOutput) public {
        // Ensure the given program output has been validateds
        require(outputFactIsValid(programOutput), "MISSING_CAIRO_PROOF");

        // Ensure the given program output is starting from our current state
        bytes32 startingHash = readStartingHash(programOutput);
        require(startingHash == currentState.hash, "INCORRECT_STARTING_STATE");

        // Ensure the new state extends the genesis and is heavier than the
        // current state
        CircuitState memory newState = readNewState(programOutput);
        require(newState.genesisHash == currentState.genesisHash, "INCORRECT_GENESIS_HASH");
        require(newState.weight > currentState.weight, "NOT_ENOUGH_WEIGHT");

        // All checks passed; update the state.
        currentState = newState;
    }

    //
    // Deserializing functions
    //

    // getStartingHashFromOutput parses the starting state hash from a program
    // output.
    function readStartingHash(uint256[] calldata programOutput) public pure returns (bytes32) {
        return readHashFromSHAState(programOutput, 28);
    }

    // getNewStateFromOutput parses a serialized circuit state from a program
    // output.
    function readNewState(uint256[] calldata programOutput) public pure returns (CircuitState memory) {
        // The program output is two equal sized states, and we want second one
        uint offset = programOutput.length / 2;

        // Read from the output into a struct
        CircuitState memory newState;
        newState.genesisHash = bytes32(readUint256(programOutput, 0));
        newState.height = uint64(programOutput[offset+2]);
        newState.weight = readUint256(programOutput, offset+3);
        newState.target = readUint256(programOutput, offset+5);
        newState.periodStartedAt = uint64(programOutput[offset+7]);
        newState.header.version = _readUint32(programOutput[offset+8]);
        newState.header.prevHash = readHashFromSHAState(programOutput, offset+9);
        newState.header.merkleRoot = readHashFromSHAState(programOutput, offset+17);
        newState.header.time = _readUint32(programOutput[offset+25]);
        newState.header.nbits = _readUint32(programOutput[offset+26]);
        newState.header.nonce = _readUint32(programOutput[offset+27]);
        newState.hash = readHashFromSHAState(programOutput, offset+28);
        return newState;
    }

    // getHashFromOutputSHAState converts a SHA state from inside the program
    // output into a bytes32 in big-endian order.
    function readHashFromSHAState(uint256[] calldata programOutput, uint offset) public pure returns (bytes32) {
        return bytes32(
            _reverse4ByteWord_uint256(programOutput[offset]) +
            (_reverse4ByteWord_uint256(programOutput[offset+1]) << 32) +
            (_reverse4ByteWord_uint256(programOutput[offset+2]) << 64) +
            (_reverse4ByteWord_uint256(programOutput[offset+3]) << 96) +
            (_reverse4ByteWord_uint256(programOutput[offset+4]) << 128) +
            (_reverse4ByteWord_uint256(programOutput[offset+5]) << 160) +
            (_reverse4ByteWord_uint256(programOutput[offset+6]) << 192) +
            (_reverse4ByteWord_uint256(programOutput[offset+7]) << 224));
    }

    function readUint256(uint256[] calldata programOutput, uint offset) public pure returns (uint256) {
        return (programOutput[offset+1] << 128) + programOutput[offset];
    }

    //
    //  Utility functions
    //

    function _reverse4ByteWord_uint256(uint256 input) internal pure returns (uint256 v_256) {
        uint32 v = uint32(input);

        // swap bytes
        v = ((v & 0xFF00FF00) >> 8) |
        ((v & 0x00FF00FF) << 8);

        // swap 2-byte long pairs
        v = (v >> 16) | (v << 16);

        // convert to uint256
        v_256 = uint256(v);
        return v_256;
    }

    function _reverse4ByteWord(uint32 input) internal pure returns (uint32 v) {
        v = input;

        // swap bytes
        v = ((v & 0xFF00FF00) >> 8) |
        ((v & 0x00FF00FF) << 8);

        // swap 2-byte long pairs
        v = (v >> 16) | (v << 16);
    }

    function _readUint32(uint256 word) internal pure returns (uint32) {
        return _reverse4ByteWord(uint32(word & 0xFFFFFFFF));
    }
}
