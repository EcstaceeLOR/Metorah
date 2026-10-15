// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MetorahClaimLedger} from "../src/MetorahClaimLedger.sol";

// No external dependencies. This ledger is an accounting fixture ONLY.
interface VmLedger34 {
    function prank(address sender) external;
    function expectRevert() external;
    function chainId(uint256 newChainId) external;
    function deal(address account, uint256 newBalance) external;
}

contract MetorahClaimLedgerAdversarialTest {
    VmLedger34 private constant vm = VmLedger34(address(uint160(uint256(keccak256("hevm cheat code")))));
    bytes32 private constant MIGRATION = keccak256("metorah-34-migration");
    bytes32 private constant FREEZE = keccak256("metorah-34-freeze-unverified");
    bytes32 private constant MANIFEST = keccak256("metorah-34-manifest-unverified");
    bytes32 private constant SOURCE_A = keccak256("source-a");
    bytes32 private constant SOURCE_B = keccak256("source-b");
    address private constant ALICE = address(0xA11CE);
    address private constant BOB = address(0xB0B);
    address private constant MALLORY = address(0xBAD);

    MetorahClaimLedger internal ledger;

    function setUp() public {
        ledger = new MetorahClaimLedger(MIGRATION, FREEZE, 100);
    }

    function _root(bytes32 a, bytes32 b) internal pure returns (bytes32) {
        return a < b ? keccak256(abi.encodePacked(a, b)) : keccak256(abi.encodePacked(b, a));
    }

    function _single(uint256 amount) internal returns (bytes32[] memory proof) {
        ledger.commitRoot(ledger.leafHash(0, SOURCE_A, ALICE, amount), MANIFEST);
        proof = new bytes32[](0);
    }

    function testConstructorRejectsUnboundDomainAndEmptyAllocation() public {
        vm.expectRevert();
        new MetorahClaimLedger(bytes32(0), FREEZE, 100);
        vm.expectRevert();
        new MetorahClaimLedger(MIGRATION, bytes32(0), 100);
        vm.expectRevert();
        new MetorahClaimLedger(MIGRATION, FREEZE, 0);
    }

    function testRootIsPrivilegedAndImmutable() public {
        vm.prank(MALLORY);
        vm.expectRevert();
        ledger.commitRoot(bytes32(uint256(2)), MANIFEST);
        bytes32[] memory proof = _single(100);
        vm.expectRevert();
        ledger.commitRoot(bytes32(uint256(3)), MANIFEST);
        vm.prank(ALICE);
        ledger.claim(0, SOURCE_A, 100, proof);
        assert(ledger.credits(ALICE) == 100);
    }

    function testZeroAmountAndInvalidProofCannotCreateCredit() public {
        bytes32[] memory proof = _single(100);
        vm.prank(ALICE);
        vm.expectRevert();
        ledger.claim(0, SOURCE_A, 0, proof);
        vm.prank(ALICE);
        vm.expectRevert();
        ledger.claim(0, SOURCE_B, 100, proof);
        assert(ledger.totalClaimed() == 0);
        assert(!ledger.claimed(0));
    }

    function testCrossIndexReplayAndSecondClaimAreRejected() public {
        bytes32[] memory proof = _single(100);
        vm.prank(ALICE);
        vm.expectRevert();
        ledger.claim(1, SOURCE_A, 100, proof);
        vm.prank(ALICE);
        ledger.claim(0, SOURCE_A, 100, proof);
        vm.prank(ALICE);
        vm.expectRevert();
        ledger.claim(0, SOURCE_A, 100, proof);
        assert(ledger.totalClaimed() == 100);
    }

    function testCapPreventsExcessEvenWhenMerkleLeavesAreValid() public {
        bytes32 alice = ledger.leafHash(0, SOURCE_A, ALICE, 80);
        bytes32 bob = ledger.leafHash(1, SOURCE_B, BOB, 80);
        ledger.commitRoot(_root(alice, bob), MANIFEST);
        bytes32[] memory proofA = new bytes32[](1);
        proofA[0] = bob;
        bytes32[] memory proofB = new bytes32[](1);
        proofB[0] = alice;
        vm.prank(ALICE);
        ledger.claim(0, SOURCE_A, 80, proofA);
        vm.prank(BOB);
        vm.expectRevert();
        ledger.claim(1, SOURCE_B, 80, proofB);
        assert(ledger.totalClaimed() == 80);
        assert(!ledger.claimed(1));
        assert(ledger.credits(BOB) == 0);
    }

    function testChainIdDomainReplayRejected() public {
        uint256 previousChain = block.chainid;
        bytes32[] memory proof = _single(100);
        vm.chainId(previousChain + 1);
        vm.prank(ALICE);
        vm.expectRevert();
        ledger.claim(0, SOURCE_A, 100, proof);
        vm.chainId(previousChain);
        vm.prank(ALICE);
        ledger.claim(0, SOURCE_A, 100, proof);
    }

    function testMigrationDomainReplayRejected() public {
        bytes32[] memory proof = _single(100);
        MetorahClaimLedger other = new MetorahClaimLedger(keccak256("other-migration"), FREEZE, 100);
        other.commitRoot(ledger.merkleRoot(), MANIFEST);
        vm.prank(ALICE);
        vm.expectRevert();
        other.claim(0, SOURCE_A, 100, proof);
    }

    function testOverflowInputFailsWithoutMarkingClaim() public {
        // Root can be committed by privileged admin despite exceeding cap;
        // claim MUST fail-closed. This is NOT source allocation verification.
        bytes32[] memory proof = _single(type(uint256).max);
        vm.prank(ALICE);
        vm.expectRevert();
        ledger.claim(0, SOURCE_A, type(uint256).max, proof);
        assert(!ledger.claimed(0));
        assert(ledger.totalClaimed() == 0);
    }

    function testRecordsOnlyCreditsAndDoesNotTransferRealAssets() public {
        vm.deal(ALICE, 1 ether);
        uint256 beforeBalance = ALICE.balance;
        bytes32[] memory proof = _single(100);
        vm.prank(ALICE);
        ledger.claim(0, SOURCE_A, 100, proof);
        assert(ALICE.balance == beforeBalance);
        assert(address(ledger).balance == 0);
        assert(ledger.credits(ALICE) == 100);
    }

    function testACompromisedAdministratorCanCommitFabricatedRoot() public {
        // Documented systemic risk: fixture explicitly demonstrates that the
        // administrator can supply a fabricated allocation despite no source proof.
        bytes32[] memory proof = _single(100);
        vm.prank(ALICE);
        ledger.claim(0, SOURCE_A, 100, proof);
        assert(ledger.credits(ALICE) == 100);
        assert(ledger.sourceFreezeEvidenceHash() == FREEZE);
        // The presence of this opaque hash DOES NOT authenticate Portaldot source finality.
    }
}
