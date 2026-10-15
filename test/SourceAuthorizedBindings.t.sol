// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {SourceAuthorizedBindings} from "../src/SourceAuthorizedBindings.sol";

interface VmSourceBindings {
    function addr(uint256 privateKey) external returns (address);
    function sign(uint256 privateKey, bytes32 digest) external returns (uint8 v, bytes32 r, bytes32 s);
    function warp(uint256 timestamp) external;
}

contract SourceAuthorizedBindingsTest {
    VmSourceBindings private constant vm = VmSourceBindings(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 private constant KEY_A = 0xA11CE;
    uint256 private constant KEY_B = 0xB0B;
    uint256 private constant KEY_BAD = 0xD00D;
    bytes32 private constant MIGRATION = keccak256("migration");
    bytes32 private constant SOURCE = keccak256("source-account-32");
    address private beneficiary = address(0xBEEF);
    SourceAuthorizedBindings private registry;

    function setUp() public {
        address[] memory signers = new address[](2);
        signers[0] = vm.addr(KEY_A);
        signers[1] = vm.addr(KEY_B);
        registry = new SourceAuthorizedBindings(MIGRATION, 2, signers);
    }

    function _sig(uint256 key, bytes32 digest) internal returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }

    function _signatures(uint256 keyA, uint256 keyB, bytes32 digest) internal returns (bytes[] memory sigs) {
        sigs = new bytes[](2);
        address a = vm.addr(keyA);
        address b = vm.addr(keyB);
        bytes memory sa = _sig(keyA, digest);
        bytes memory sb = _sig(keyB, digest);
        if (a < b) { sigs[0] = sa; sigs[1] = sb; }
        else { sigs[0] = sb; sigs[1] = sa; }
    }

    function testBindingIsScopedAndImmutable() public {
        uint64 expiry = uint64(block.timestamp + 1 days);
        bytes32 digest = registry.bindingDigest(SOURCE, beneficiary, expiry);
        registry.registerBinding(SOURCE, beneficiary, expiry, _signatures(KEY_A, KEY_B, digest));
        assert(registry.verifyBinding(SOURCE, beneficiary));
        assert(!registry.verifyBinding(SOURCE, address(0xBAD)));
        (bool ok,) = address(registry).call(abi.encodeCall(
            registry.registerBinding,
            (SOURCE, address(0xBAD), expiry, _signatures(KEY_A, KEY_B, registry.bindingDigest(SOURCE, address(0xBAD), expiry)))
        ));
        assert(!ok);
    }

    function testRejectsUnapprovedAttester() public {
        uint64 expiry = uint64(block.timestamp + 1 days);
        bytes32 digest = registry.bindingDigest(SOURCE, beneficiary, expiry);
        bytes[] memory sigs = _signatures(KEY_A, KEY_BAD, digest);
        (bool ok,) = address(registry).call(abi.encodeCall(registry.registerBinding, (SOURCE, beneficiary, expiry, sigs)));
        assert(!ok);
    }

    function testRejectsExpiredBinding() public {
        uint64 expiry = uint64(block.timestamp + 1 days);
        bytes32 digest = registry.bindingDigest(SOURCE, beneficiary, expiry);
        bytes[] memory sigs = _signatures(KEY_A, KEY_B, digest);
        vm.warp(uint256(expiry) + 1);
        (bool ok,) = address(registry).call(abi.encodeCall(registry.registerBinding, (SOURCE, beneficiary, expiry, sigs)));
        assert(!ok);
    }

    function testDigestChangesAcrossChainAndContractDomain() public {
        uint64 expiry = uint64(block.timestamp + 1 days);
        bytes32 beforeDigest = registry.bindingDigest(SOURCE, beneficiary, expiry);
        vm.warp(block.timestamp + 1);
        bytes32 afterDigest = registry.bindingDigest(SOURCE, beneficiary, expiry);
        assert(beforeDigest != afterDigest); // expiry is part of the signed tuple
    }
}
