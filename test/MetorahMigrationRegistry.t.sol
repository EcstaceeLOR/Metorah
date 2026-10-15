// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MetorahMigrationRegistry} from "../src/MetorahMigrationRegistry.sol";
import {MetorahClaimLedger} from "../src/MetorahClaimLedger.sol";

interface VmRegistry {
    function prank(address sender) external;
    function expectRevert() external;
    function chainId(uint256 newChainId) external;
}

contract MetorahMigrationRegistryTest {
    VmRegistry private constant vm = VmRegistry(address(uint160(uint256(keccak256("hevm cheat code")))));
    MetorahMigrationRegistry private registry;
    address private constant ALICE = address(0xA11CE);
    address private constant MALLORY = address(0xBAD);
    bytes32 private constant FREEZE = keccak256("offline-unverified-source-evidence");
    bytes32 private constant MANIFEST = keccak256("unverified-manifest");
    bytes32 private constant SOURCE_ACCOUNT = keccak256("source-account");

    function setUp() public {
        registry = new MetorahMigrationRegistry();
    }

    function _domain() private view returns (MetorahMigrationRegistry.Domain memory d) {
        d = MetorahMigrationRegistry.Domain({
            sourceGenesis: keccak256("genesis"),
            sourceContract: keccak256("substrate-source-contract"),
            destinationChainId: block.chainid,
            mode: keccak256("wasm-to-evm"),
            manifestVersion: 1,
            assetId: keccak256("test-asset")
        });
    }

    function _create() private returns (bytes32 id, address ledgerAddress) {
        return registry.createMigration(_domain(), FREEZE, 100, ALICE);
    }

    function testCreate2AddressPredictionAndRegistryLookup() public {
        MetorahMigrationRegistry.Domain memory d = _domain();
        bytes32 id = registry.migrationId(d);
        address expected = registry.predictLedger(d, FREEZE, 100);
        (bytes32 actualId, address created) = _create();
        assert(id == actualId);
        assert(expected == created);
        assert(created.code.length > 0);
        assert(registry.ledgerOf(id) == created);
        assert(registry.migrationOf(created) == id);
        MetorahClaimLedger ledger = MetorahClaimLedger(created);
        assert(ledger.migrationId() == id);
        assert(ledger.sourceFreezeEvidenceHash() == FREEZE);
        assert(ledger.totalAllocation() == 100);
        assert(ledger.administrator() == address(registry));
        assert(ledger.pendingAdministrator() == ALICE);
    }

    function testDuplicateCreationRejectedEvenWithDifferentEvidence() public {
        _create();
        vm.expectRevert();
        registry.createMigration(_domain(), keccak256("other-freeze"), 999, ALICE);
    }

    function testUnauthorizedCreationRejected() public {
        vm.prank(MALLORY);
        vm.expectRevert();
        registry.createMigration(_domain(), FREEZE, 100, MALLORY);
    }

    function testDeterministicIdsVaryWithEveryDomainComponent() public {
        MetorahMigrationRegistry.Domain memory d = _domain();
        bytes32 baseline = registry.migrationId(d);
        d.sourceGenesis = keccak256("other-genesis");
        assert(registry.migrationId(d) != baseline);
        d = _domain();
        d.sourceContract = keccak256("another-contract");
        assert(registry.migrationId(d) != baseline);
        d = _domain();
        d.mode = keccak256("evm-to-evm");
        assert(registry.migrationId(d) != baseline);
        d = _domain();
        d.manifestVersion = 2;
        assert(registry.migrationId(d) != baseline);
        d = _domain();
        d.assetId = keccak256("other-asset");
        assert(registry.migrationId(d) != baseline);
        d = _domain();
        d.destinationChainId = block.chainid + 1;
        vm.expectRevert();
        registry.migrationId(d);
        MetorahMigrationRegistry other = new MetorahMigrationRegistry();
        assert(other.migrationId(_domain()) != baseline);
    }

    function testRejectMalformedDomainTuple() public {
        MetorahMigrationRegistry.Domain memory d = _domain();
        d.sourceGenesis = bytes32(0);
        vm.expectRevert();
        registry.migrationId(d);
        d = _domain();
        d.sourceContract = bytes32(0);
        vm.expectRevert();
        registry.migrationId(d);
        d = _domain();
        d.mode = bytes32(0);
        vm.expectRevert();
        registry.migrationId(d);
        d = _domain();
        d.assetId = bytes32(0);
        vm.expectRevert();
        registry.migrationId(d);
        d = _domain();
        d.manifestVersion = 0;
        vm.expectRevert();
        registry.migrationId(d);
        d = _domain();
        d.destinationChainId = 0;
        vm.expectRevert();
        registry.migrationId(d);
    }

    function testRejectMissingEvidenceCapOrAdministrator() public {
        MetorahMigrationRegistry.Domain memory d = _domain();
        vm.expectRevert();
        registry.createMigration(d, bytes32(0), 100, ALICE);
        vm.expectRevert();
        registry.createMigration(d, FREEZE, 0, ALICE);
        vm.expectRevert();
        registry.createMigration(d, FREEZE, 100, address(0));
        vm.expectRevert();
        registry.createMigration(d, FREEZE, 100, address(registry));
        vm.expectRevert();
        registry.predictLedger(d, bytes32(0), 100);
    }

    function testTwoStepAdminHandoverAndPrivilegedCommit() public {
        (, address addressOfLedger) = _create();
        MetorahClaimLedger ledger = MetorahClaimLedger(addressOfLedger);
        vm.prank(MALLORY);
        vm.expectRevert();
        ledger.acceptAdministrator();
        vm.prank(ALICE);
        ledger.acceptAdministrator();
        assert(ledger.administrator() == ALICE);
        assert(ledger.pendingAdministrator() == address(0));
        bytes32 leaf = ledger.leafHash(0, SOURCE_ACCOUNT, ALICE, 100);
        vm.prank(MALLORY);
        vm.expectRevert();
        ledger.commitRoot(leaf, MANIFEST);
        vm.prank(ALICE);
        ledger.commitRoot(leaf, MANIFEST);
        bytes32[] memory proof = new bytes32[](0);
        vm.prank(ALICE);
        ledger.claim(0, SOURCE_ACCOUNT, 100, proof);
        assert(ledger.credits(ALICE) == 100);
        assert(ledger.totalClaimed() == 100);
    }

    function testCanNotChangeAdministratorOnceRootCommitted() public {
        // Directly deployed ledger keeps backwards-compatible creator admin.
        MetorahClaimLedger ledger = new MetorahClaimLedger(keccak256("id"), FREEZE, 100);
        ledger.proposeAdministrator(ALICE);
        ledger.commitRoot(bytes32(uint256(1)), MANIFEST);
        vm.prank(ALICE);
        vm.expectRevert();
        ledger.acceptAdministrator();
        vm.expectRevert();
        ledger.proposeAdministrator(MALLORY);
    }

    function testRejectWrongProposerAndZeroPendingAcceptance() public {
        MetorahClaimLedger ledger = new MetorahClaimLedger(keccak256("id"), FREEZE, 100);
        vm.prank(ALICE);
        vm.expectRevert();
        ledger.proposeAdministrator(MALLORY);
        vm.prank(ALICE);
        vm.expectRevert();
        ledger.acceptAdministrator();
        vm.expectRevert();
        ledger.proposeAdministrator(address(0));
        vm.expectRevert();
        ledger.proposeAdministrator(address(this));
    }

    function testCreationDoesNotAuthenticateSourceOrFundClaims() public {
        (, address created) = _create();
        assert(created.balance == 0);
        MetorahClaimLedger ledger = MetorahClaimLedger(created);
        assert(ledger.merkleRoot() == bytes32(0));
        assert(!ledger.committed());
        assert(ledger.totalClaimed() == 0);
    }
}
