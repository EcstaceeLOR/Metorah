// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {SourceAuthorizedBindings} from "../src/SourceAuthorizedBindings.sol";
import {BackedTokenSettlement} from "../src/BackedTokenSettlement.sol";
import {VerifiedTokenClaimLedger} from "../src/VerifiedTokenClaimLedger.sol";

interface VmTokenClaims {
    function addr(uint256 privateKey) external returns (address);
    function sign(uint256 privateKey, bytes32 digest) external returns (uint8, bytes32, bytes32);
    function warp(uint256 timestamp) external;
    function prank(address sender) external;
}

contract MockClaimToken {
    mapping(address => uint256) public balanceOf;
    function mint(address to, uint256 amount) external { balanceOf[to] += amount; }
    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(balanceOf[from] >= amount, "balance");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract VerifiedTokenClaimLedgerTest {
    VmTokenClaims private constant vm = VmTokenClaims(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 private constant KEY_A = 0xA11CE;
    uint256 private constant KEY_B = 0xB0B;
    uint256 private constant KEY_C = 0xCAFE;
    bytes32 private constant MIGRATION = keccak256("migration-e3");
    bytes32 private constant FREEZE = keccak256("freeze-evidence");
    bytes32 private constant MANIFEST = keccak256("manifest-v1");
    bytes32 private constant SOURCE = keccak256("source-account");
    address private constant BENEFICIARY = address(0xBEEF);

    SourceAuthorizedBindings private bindings;
    BackedTokenSettlement private settlement;
    VerifiedTokenClaimLedger private ledger;
    MockClaimToken private token;

    function setUp() public {
        address[] memory attesters = new address[](2);
        attesters[0] = vm.addr(KEY_A);
        attesters[1] = vm.addr(KEY_B);
        bindings = new SourceAuthorizedBindings(MIGRATION, 2, attesters);
        uint64 expiry = uint64(block.timestamp + 30 days);
        bytes32 bindingDigest = bindings.bindingDigest(SOURCE, BENEFICIARY, expiry);
        bindings.registerBinding(SOURCE, BENEFICIARY, expiry, _signatures(bindingDigest));

        address[] memory signers = new address[](3);
        signers[0] = vm.addr(KEY_A);
        signers[1] = vm.addr(KEY_B);
        signers[2] = vm.addr(KEY_C);
        ledger = new VerifiedTokenClaimLedger(MIGRATION, FREEZE, 1000, 1 days, 2, signers, address(bindings));
        token = new MockClaimToken();
        settlement = new BackedTokenSettlement(address(token), address(ledger), address(this), 1000);
        ledger.configureSettlement(address(settlement));
        token.mint(address(this), 1000);
        settlement.fund(1000);
    }

    function _sig(uint256 key, bytes32 digest) internal returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }

    function _signatures(bytes32 digest) internal returns (bytes[] memory out) {
        out = new bytes[](2);
        bytes memory a = _sig(KEY_A, digest);
        bytes memory b = _sig(KEY_B, digest);
        if (vm.addr(KEY_A) < vm.addr(KEY_B)) { out[0] = a; out[1] = b; }
        else { out[0] = b; out[1] = a; }
    }

    function testClaimTransfersRealBackedTokensOnlyToBoundBeneficiary() public {
        bytes32 root = ledger.leafHash(7, SOURCE, BENEFICIARY, 400);
        uint64 activation = uint64(block.timestamp + 1 days);
        ledger.proposeEvidence(root, MANIFEST, activation, _signatures(ledger.attestationDigest(root, MANIFEST, activation)));
        vm.warp(activation);
        ledger.activate();

        bytes32[] memory proof = new bytes32[](0);
        vm.prank(BENEFICIARY);
        ledger.claim(7, SOURCE, 400, proof);

        assert(token.balanceOf(BENEFICIARY) == 400);
        assert(token.balanceOf(address(settlement)) == 600);
        assert(ledger.totalClaimed() == 400);
        assert(settlement.totalSettled() == 400);
        assert(settlement.availableBacking() == 600);
    }

    function testUnboundOrWrongBeneficiaryCannotClaim() public {
        bytes32 root = ledger.leafHash(7, SOURCE, BENEFICIARY, 400);
        uint64 activation = uint64(block.timestamp + 1 days);
        ledger.proposeEvidence(root, MANIFEST, activation, _signatures(ledger.attestationDigest(root, MANIFEST, activation)));
        vm.warp(activation);
        ledger.activate();
        bytes32[] memory proof = new bytes32[](0);
        (bool ok,) = address(ledger).call(abi.encodeCall(ledger.claim, (7, SOURCE, 400, proof)));
        assert(!ok);
        vm.prank(BENEFICIARY);
        ledger.claim(7, SOURCE, 400, proof);
        assert(token.balanceOf(BENEFICIARY) == 400);
    }

    function testCannotClaimSameIndexTwice() public {
        bytes32 root = ledger.leafHash(7, SOURCE, BENEFICIARY, 400);
        uint64 activation = uint64(block.timestamp + 1 days);
        ledger.proposeEvidence(root, MANIFEST, activation, _signatures(ledger.attestationDigest(root, MANIFEST, activation)));
        vm.warp(activation);
        ledger.activate();
        bytes32[] memory proof = new bytes32[](0);
        vm.prank(BENEFICIARY);
        ledger.claim(7, SOURCE, 400, proof);
        vm.prank(BENEFICIARY);
        (bool ok,) = address(ledger).call(abi.encodeCall(ledger.claim, (7, SOURCE, 400, proof)));
        assert(!ok);
        assert(token.balanceOf(BENEFICIARY) == 400);
    }

    function testCannotProposeBeforeSettlementConfigured() public {
        address[] memory signers = new address[](2);
        signers[0] = vm.addr(KEY_A);
        signers[1] = vm.addr(KEY_B);
        VerifiedTokenClaimLedger unconfigured = new VerifiedTokenClaimLedger(MIGRATION, FREEZE, 1000, 1 days, 2, signers, address(bindings));
        bytes32 root = unconfigured.leafHash(0, SOURCE, BENEFICIARY, 10);
        uint64 activation = uint64(block.timestamp + 1 days);
        (bool ok,) = address(unconfigured).call(abi.encodeCall(unconfigured.proposeEvidence, (root, MANIFEST, activation, _signatures(unconfigured.attestationDigest(root, MANIFEST, activation)))));
        assert(!ok);
    }
}
