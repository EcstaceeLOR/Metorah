// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {VerifiedEvidenceLedger} from "../src/VerifiedEvidenceLedger.sol";

interface VmVerifiedEvidence {
    function addr(uint256 privateKey) external returns (address);
    function sign(uint256 privateKey, bytes32 digest) external returns (uint8 v, bytes32 r, bytes32 s);
    function warp(uint256 timestamp) external;
}

contract VerifiedEvidenceLedgerTest {
    VmVerifiedEvidence private constant vm = VmVerifiedEvidence(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 private constant KEY_A = 0xA11CE;
    uint256 private constant KEY_B = 0xB0B;
    uint256 private constant KEY_C = 0xCAFE;
    bytes32 private constant MIGRATION = keccak256("verified-migration");
    bytes32 private constant FREEZE = keccak256("freeze-evidence");
    bytes32 private constant MANIFEST = keccak256("manifest-v1");
    bytes32 private constant SOURCE = keccak256("source-account");
    address private alice;
    VerifiedEvidenceLedger private ledger;

    function setUp() public {
        alice = address(0xA11CE);
        address[] memory signers = new address[](3);
        signers[0] = vm.addr(KEY_A);
        signers[1] = vm.addr(KEY_B);
        signers[2] = vm.addr(KEY_C);
        // Constructor requires signer order only for signatures, not this list.
        ledger = new VerifiedEvidenceLedger(MIGRATION, FREEZE, 100, 1 days, 2, signers);
    }

    function _sig(uint256 key, bytes32 digest) internal returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }

    function _propose(bytes32 root, uint64 activation) internal {
        bytes32 digest = ledger.attestationDigest(root, MANIFEST, activation);
        address a = vm.addr(KEY_A);
        address b = vm.addr(KEY_B);
        bytes memory sigA = _sig(KEY_A, digest);
        bytes memory sigB = _sig(KEY_B, digest);
        bytes[] memory signatures = new bytes[](2);
        if (a < b) { signatures[0] = sigA; signatures[1] = sigB; }
        else { signatures[0] = sigB; signatures[1] = sigA; }
        ledger.proposeEvidence(root, MANIFEST, activation, signatures);
    }

    function testRequiresQuorumAndDelayedActivationBeforeClaim() public {
        uint64 activation = uint64(block.timestamp + 1 days);
        bytes32 root = ledger.leafHash(0, SOURCE, address(this), 100);
        _propose(root, activation);
        bytes32[] memory proof = new bytes32[](0);
        (bool ok,) = address(ledger).call(abi.encodeCall(ledger.claim, (0, SOURCE, 100, proof)));
        assert(!ok);
        (ok,) = address(ledger).call(abi.encodeCall(ledger.activate, ()));
        assert(!ok);
        vm.warp(activation);
        ledger.activate();
        ledger.claim(0, SOURCE, 100, proof);
        assert(ledger.credits(address(this)) == 100);
    }

    function testRejectsUnauthorizedSigner() public {
        uint64 activation = uint64(block.timestamp + 1 days);
        bytes32 root = ledger.leafHash(0, SOURCE, alice, 100);
        bytes32 digest = ledger.attestationDigest(root, MANIFEST, activation);
        bytes[] memory signatures = new bytes[](2);
        signatures[0] = _sig(KEY_A, digest);
        signatures[1] = _sig(0xD00D, digest);
        address a = vm.addr(KEY_A);
        address bad = vm.addr(0xD00D);
        if (a > bad) { bytes memory temp = signatures[0]; signatures[0] = signatures[1]; signatures[1] = temp; }
        (bool ok,) = address(ledger).call(abi.encodeCall(ledger.proposeEvidence, (root, MANIFEST, activation, signatures)));
        assert(!ok);
    }

    function testRejectsActivationTimeBeforeReviewDelay() public {
        uint64 activation = uint64(block.timestamp + 1);
        bytes32 root = ledger.leafHash(0, SOURCE, alice, 100);
        bytes32 digest = ledger.attestationDigest(root, MANIFEST, activation);
        bytes[] memory signatures = new bytes[](2);
        address a = vm.addr(KEY_A);
        address b = vm.addr(KEY_B);
        bytes memory sigA = _sig(KEY_A, digest);
        bytes memory sigB = _sig(KEY_B, digest);
        if (a < b) { signatures[0] = sigA; signatures[1] = sigB; }
        else { signatures[0] = sigB; signatures[1] = sigA; }
        (bool ok,) = address(ledger).call(abi.encodeCall(ledger.proposeEvidence, (root, MANIFEST, activation, signatures)));
        assert(!ok);
    }
}
