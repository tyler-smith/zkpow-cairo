// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "forge-std/Test.sol";
import "../src/ZKPOW.sol";

bytes32 constant _genesisHash = 0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f;

contract MockFactRegistry is IFactRegistry {
    mapping(bytes32 => bool) public facts;

    function isValid(bytes32 fact) external view returns (bool) {
        return facts[fact];
    }

    function setFact(bytes32 fact, bool isValid) external {
        facts[fact] = isValid;
    }
}

contract ZKPOWTest is Test {
    ZKPOW public zkpow;
    MockFactRegistry internal facts;

    uint256[] testProgramOutput_0_to_32 = [106293530757178079532609205239393608303, 31235661622419893084429971, 0, 4295032833, 0, 0, 79226953588444722964369244160, 1231006505, 16777216, 0, 0, 0, 0, 0, 0, 0, 0, 1000599037, 2054886066, 2059873342, 1735823201, 2143820739, 2290766130, 983546026, 1260281418, 699096905, 4294901789, 497822588, 1877117962, 3069293426, 3248923206, 2925786959, 2468250469, 3780774044, 1758861568, 0, 106293530757178079532609205239393608303, 31235661622419893084429971, 32, 141736083489, 0, 0, 79226953588444722964369244160, 1231006505, 16777216, 3302189495, 599969691, 3812421645, 3944595434, 210554130, 3289772692, 889127063, 0, 3384868106, 3887568700, 1123851837, 3720964022, 3809040139, 1913647444, 348160869, 4026898731, 3821365321, 4294901789, 149012493, 3824576077, 1525903458, 3107256707, 3977262050, 18563785, 2957456679, 1820117989, 0];
    uint256[] testProgramOutput_32_to_2024 = [106293530757178079532609205239393608303, 31235661622419893084429971, 32, 4295032833, 0, 0, 79226953588444722964369244160, 1231006505, 16777216, 3302189495, 599969691, 3812421645, 3944595434, 210554130, 3289772692, 889127063, 0, 3384868106, 3887568700, 1123851837, 3720964022, 3809040139, 1913647444, 348160869, 4026898731, 3821365321, 4294901789, 149012493, 3824576077, 1525903458, 3107256707, 3977262050, 18563785, 2957456679, 1820117989, 0, 106293530757178079532609205239393608303, 31235661622419893084429971, 2024, 8560000436169, 0, 0, 79226953588444722964369244160, 1233063531, 16777216, 1015981305, 2680999951, 814319377, 49095274, 3237632299, 3355082316, 3435162970, 0, 2206501268, 2392060065, 3650822769, 3320648776, 1741797713, 936348202, 1264165434, 4286980, 3861806921, 4294901789, 610647303, 3346907116, 2089334572, 3087763282, 1302347825, 1490888986, 1661482018, 3414799008, 0];
    function setUp() public {
        CircuitState memory initialState;
        initialState.genesisHash = _genesisHash;
        initialState.height = 0;
        initialState.weight = 4295032833;
        initialState.target = 0xffff0000000000000000000000000000000000000000000000000000;
        initialState.periodStartedAt = 1231006505;
        initialState.header.version = 1;
        initialState.header.prevHash = 0x0000000000000000000000000000000000000000000000000000000000000000;
        initialState.header.merkleRoot = 0x0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098;
        initialState.header.time = 1231006505;
        initialState.header.nbits = 0x1d00ffff;
        initialState.header.nonce = 497822588;
        initialState.hash = _genesisHash;

        facts = new MockFactRegistry();
        zkpow = new ZKPOW(initialState, 0, IFactRegistry(facts));
    }

    function testGetStartingHashFromOutput() public {
        bytes32 startingHash = zkpow.readStartingHash(testProgramOutput_0_to_32);
        assertEq(startingHash, _genesisHash);
    }

    function testNewStateFromOutput() public {
        CircuitState memory newState = zkpow.readNewState(testProgramOutput_0_to_32);
        assertEq(newState.genesisHash, _genesisHash);
        assertEq(newState.height, 32);
        assertEq(newState.weight, 141736083489);
        assertEq(newState.periodStartedAt, 1231006505);
        assertEq(newState.header.version, 1);
        assertEq(newState.header.prevHash, 0x000000009700ff3494f215c412cd8c0ceabf1deb0df03ce39bcfc223b769d3c4);
        assertEq(newState.header.merkleRoot, 0x2b9905f06583c01454f10f720b5709e3b667c9dd3d9efc423c97b7e70afdc0c9);
        assertEq(newState.header.time, 1231603171);
        assertEq(newState.header.nbits, 0x1d00ffff);
        assertEq(newState.header.nonce, 0x0dc0e108);
        assertEq(newState.hash, 0x00000000e5cb7c6c273547b0c9421b01e23310ed83f934b96270f35a4d66f6e3);
    }

    function testUpdateState_failure_missing_proof() public {
        vm.expectRevert(abi.encodePacked("MISSING_CAIRO_PROOF"));
        zkpow.updateState(testProgramOutput_0_to_32);
    }

    function testUpdateState_failure_not_enough_weight() public {
        assertEq(zkpow.height(), 0);

        // Set the new weight super low
        uint256[] memory newOutput = testProgramOutput_0_to_32;
        newOutput[(newOutput.length/2)+3] = 100;
        newOutput[(newOutput.length/2)+4] = 0;
        facts.setFact(zkpow.calculateFact(newOutput), true);

        // We should fail to update
        vm.expectRevert(abi.encodePacked("NOT_ENOUGH_WEIGHT"));
        zkpow.updateState(newOutput);
        assertEq(zkpow.height(), 0);
    }

    function testUpdateState_failure_incorrect_genesis_hash() public {
        assertEq(zkpow.height(), 0);

        // Set an incorrect genesis hash
        uint256[] memory newOutput = testProgramOutput_0_to_32;
        newOutput[0] = 0;
        facts.setFact(zkpow.calculateFact(newOutput), true);

        // We should fail to update
        vm.expectRevert(abi.encodePacked("INCORRECT_GENESIS_HASH"));
        zkpow.updateState(newOutput);
        assertEq(zkpow.height(), 0);
    }

    function testUpdateState_failure_incorrect_starting_state() public {
        // Update so our starting state is the end state of our test output
        facts.setFact(zkpow.calculateFact(testProgramOutput_0_to_32), true);
        assertEq(zkpow.height(), 0);
        zkpow.updateState(testProgramOutput_0_to_32);
        assertEq(zkpow.height(), 32);

        // We should fail to update
        vm.expectRevert(abi.encodePacked("INCORRECT_STARTING_STATE"));
        zkpow.updateState(testProgramOutput_0_to_32);
        assertEq(zkpow.height(), 32);
    }

    function testUpdateState_success() public {
        // Ensure the current state is the genesis state
        CircuitState memory currentState = zkpow.getCurrentState();
        assertEq(currentState.genesisHash, _genesisHash);
        assertEq(currentState.height, 0);
        assertEq(currentState.weight, 4295032833);
        assertEq(currentState.periodStartedAt, 1231006505);
        assertEq(currentState.header.version, 1);
        assertEq(currentState.header.prevHash, 0x0000000000000000000000000000000000000000000000000000000000000000);
        assertEq(currentState.header.merkleRoot, 0x0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098);
        assertEq(currentState.header.time, 1231006505);
        assertEq(currentState.header.nbits, 0x1d00ffff);
        assertEq(currentState.header.nonce, 497822588);
        assertEq(currentState.hash, _genesisHash);

        // Add a proof and update the state from 0 to 32
        facts.setFact(zkpow.calculateFact(testProgramOutput_0_to_32), true);
        zkpow.updateState(testProgramOutput_0_to_32);

        // Ensure all state elements were correctly updated
        CircuitState memory newState = zkpow.getCurrentState();
        assertEq(newState.genesisHash, _genesisHash);
        assertEq(newState.height, 32);
        assertEq(newState.weight, 141736083489);
        assertEq(newState.periodStartedAt, 1231006505);
        assertEq(newState.header.version, 1);
        assertEq(newState.header.prevHash, 0x000000009700ff3494f215c412cd8c0ceabf1deb0df03ce39bcfc223b769d3c4);
        assertEq(newState.header.merkleRoot, 0x2b9905f06583c01454f10f720b5709e3b667c9dd3d9efc423c97b7e70afdc0c9);
        assertEq(newState.header.time, 1231603171);
        assertEq(newState.header.nbits, 0x1d00ffff);
        assertEq(newState.header.nonce, 0x0dc0e108);
        assertEq(newState.hash, 0x00000000e5cb7c6c273547b0c9421b01e23310ed83f934b96270f35a4d66f6e3);

        // Now update from block 32 to block 2024
        facts.setFact(zkpow.calculateFact(testProgramOutput_32_to_2024), true);
        zkpow.updateState(testProgramOutput_32_to_2024);
        newState = zkpow.getCurrentState();
        assertEq(newState.genesisHash, _genesisHash);
        assertEq(newState.height, 2024);
        assertEq(newState.weight, 8560000436169);
        assertEq(newState.periodStartedAt, 1233063531);
        assertEq(newState.header.version, 1);
        assertEq(newState.header.prevHash, 0x000000005a6dc0cc4c7efac72b59fac06a22ed02118789300fd0cc9ff9a48e3c);
        assertEq(newState.header.merkleRoot, 0x046a41003aa2594b2a8acf3751b9d1674814edc571229bd9a1f0938e94898483);
        assertEq(newState.header.time, 1233071846);
        assertEq(newState.header.nbits, 0x1d00ffff);
        assertEq(newState.header.nonce, 0x07bd6524);
        assertEq(newState.hash, 0x00000000a0b289cb223408631a29dd583140a04d52870bb82cb7887cecbf7dc7);
    }
}
