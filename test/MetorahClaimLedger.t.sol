// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MetorahClaimLedger} from "../src/MetorahClaimLedger.sol";

// Self-contained Foundry tests: no forge-std dependency.
interface Vm {
    function prank(address sender) external;
    function expectRevert() external;
}

contract MetorahClaimLedgerTest {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    bytes32 private constant MIGRATION = keccak256("statelift-test-migration");
    bytes32 private constant FREEZE = keccak256("statelift-test-source-freeze");
    bytes32 private constant MANIFEST = keccak256("statelift-test-manifest");
    bytes32 private constant SOURCE_A = keccak256("source-account-alice");
    bytes32 private constant SOURCE_B = keccak256("source-account-bob");
    address private constant ALICE = address(0xA11CE);
    address private constant BOB = address(0xB0B);
    address private constant MALLORY = address(0xBAD);

    MetorahClaimLedger private ledger;

    function setUp() public {
        ledger = new MetorahClaimLedger(MIGRATION, FREEZE, 100);
    }

    function _sortedHash(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return a < b ? keccak256(abi.encodePacked(a, b)) : keccak256(abi.encodePacked(b, a));
    }

    function _commitSingle() internal {
        ledger.commitRoot(ledger.leafHash(0, SOURCE_A, ALICE, 100), MANIFEST);
    }

    function testSingleLeafClaim() public {
        _commitSingle();
        bytes32[] memory proof = new bytes32[](0);
        vm.prank(ALICE);
        ledger.claim(0, SOURCE_A, 100, proof);
        assert(ledger.claimed(0));
        assert(ledger.credits(ALICE) == 100);
        assert(ledger.totalClaimed() == ledger.totalAllocation());
    }

    function testRejectClaimBeforeCommit() public {
        bytes32[] memory proof = new bytes32[](0);
        vm.expectRevert();
        vm.prank(ALICE);
        ledger.claim(0, SOURCE_A, 100, proof);
    }

    function testRejectUnauthorizedRootCommit() public {
        vm.expectRevert();
        vm.prank(MALLORY);
        ledger.commitRoot(bytes32(uint256(1)), MANIFEST);
    }

    function testRejectRootReplacement() public {
        _commitSingle();
        vm.expectRevert();
        ledger.commitRoot(bytes32(uint256(2)), MANIFEST);
    }

    function testRejectZeroRootOrManifest() public {
        vm.expectRevert();
        ledger.commitRoot(bytes32(0), MANIFEST);
        vm.expectRevert();
        ledger.commitRoot(bytes32(uint256(1)), bytes32(0));
    }

    function testRejectWrongBeneficiary() public {
        _commitSingle();
        bytes32[] memory proof = new bytes32[](0);
        vm.expectRevert();
        vm.prank(MALLORY);
        ledger.claim(0, SOURCE_A, 100, proof);
        assert(!ledger.claimed(0));
        assert(ledger.totalClaimed() == 0);
    }

    function testRejectWrongSourceAccountOrAmount() public {
        _commitSingle();
        bytes32[] memory proof = new bytes32[](0);
        vm.expectRevert();
        vm.prank(ALICE);
        ledger.claim(0, SOURCE_B, 100, proof);
        vm.expectRevert();
        vm.prank(ALICE);
        ledger.claim(0, SOURCE_A, 99, proof);
        assert(ledger.totalClaimed() == 0);
    }

    function testRejectDuplicateClaim() public {
        _commitSingle();
        bytes32[] memory proof = new bytes32[](0);
        vm.prank(ALICE);
        ledger.claim(0, SOURCE_A, 100, proof);
        vm.expectRevert();
        vm.prank(ALICE);
        ledger.claim(0, SOURCE_A, 100, proof);
    }

    function testTwoLeafMerkleTree() public {
        bytes32 aliceLeaf = ledger.leafHash(0, SOURCE_A, ALICE, 60);
        bytes32 bobLeaf = ledger.leafHash(1, SOURCE_B, BOB, 40);
        ledger.commitRoot(_sortedHash(aliceLeaf, bobLeaf), MANIFEST);
        bytes32[] memory aliceProof = new bytes32[](1);
        aliceProof[0] = bobLeaf;
        bytes32[] memory bobProof = new bytes32[](1);
        bobProof[0] = aliceLeaf;
        vm.prank(ALICE);
        ledger.claim(0, SOURCE_A, 60, aliceProof);
        vm.prank(BOB);
        ledger.claim(1, SOURCE_B, 40, bobProof);
        assert(ledger.totalClaimed() == 100);
        assert(ledger.credits(ALICE) == 60);
        assert(ledger.credits(BOB) == 40);
    }

    function testRejectTamperedMerkleProof() public {
        bytes32 aliceLeaf = ledger.leafHash(0, SOURCE_A, ALICE, 60);
        bytes32 bobLeaf = ledger.leafHash(1, SOURCE_B, BOB, 40);
        ledger.commitRoot(_sortedHash(aliceLeaf, bobLeaf), MANIFEST);
        bytes32[] memory invalid = new bytes32[](1);
        invalid[0] = bytes32(uint256(12345));
        vm.expectRevert();
        vm.prank(ALICE);
        ledger.claim(0, SOURCE_A, 60, invalid);
        assert(!ledger.claimed(0));
    }

    function testTargetContractDomainIsolation() public {
        MetorahClaimLedger other = new MetorahClaimLedger(MIGRATION, FREEZE, 100);
        bytes32 aliceLeaf = ledger.leafHash(0, SOURCE_A, ALICE, 100);
        other.commitRoot(aliceLeaf, MANIFEST);
        bytes32[] memory proof = new bytes32[](0);
        vm.expectRevert();
        vm.prank(ALICE);
        other.claim(0, SOURCE_A, 100, proof);
    }
}
