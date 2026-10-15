// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MetorahManifestV1, MetorahManifestV1Harness} from "../src/MetorahManifestV1.sol";

interface ManifestTestVm {
    function expectRevert() external;
}

/**
 * Test vectors independently computed with Python hashlib.sha256 over exact
 * binary fields. THESE ARE SYNTHETIC, NEVER REAL SOURCE/FINALITY EVIDENCE.
 */
contract MetorahManifestV1ParityTest {
    ManifestTestVm private constant vm = ManifestTestVm(address(uint160(uint256(keccak256("hevm cheat code")))));
    MetorahManifestV1Harness private harness;

    bytes32 private constant VECTOR_HEADER = 0xd8a338af8ac7ac775f65646714d3de231b3d679b1ba130bd83ad511fe3f400ba;
    bytes32 private constant VECTOR_LEAF0 = 0x31fd1d1354ec4a31635782b658d76a7a24d9c568686a7063c110049b14da876f;
    bytes32 private constant VECTOR_LEAF1 = 0xd6bafe136167850d2d43217a5e0fb0ff1a4ed6329a943aab062719c3296b746e;
    bytes32 private constant VECTOR_LEAF2 = 0x3b2567bf18b77629a18970da6f354db9816d2497804bcd21c56669e34fab1b1f;
    bytes32 private constant VECTOR_NODE01 = 0xf6112ada26f352d1f304c5f44e1ba41f835e45d3e1d3f4413e879a5b5056e22f;
    bytes32 private constant VECTOR_NODE22 = 0xb50840082b5c970ae048310d964aa71e0802b1e4e5fc11439964ac9a3280f80d;
    bytes32 private constant VECTOR_ROOT = 0xd1b8fe5f690cd868bd784a22e50c71c55593ff78f91dde76ffec919efe39a060;
    bytes32 private constant VECTOR_MANIFEST = 0xe8de0555b6a4dacbaeb2bee30fad6652341a00d4f83b932c02a07240390e217f;

    function setUp() public {
        harness = new MetorahManifestV1Harness();
    }

    function _header() internal pure returns (MetorahManifestV1.Header memory h) {
        h.sourceGenesis = bytes32(hex"1111111111111111111111111111111111111111111111111111111111111111");
        h.finalizedBlockHash = bytes32(hex"2222222222222222222222222222222222222222222222222222222222222222");
        h.finalizedBlockNumber = 12345;
        h.finalizedStateRoot = bytes32(hex"3333333333333333333333333333333333333333333333333333333333333333");
        h.sourceContract = bytes32(hex"4444444444444444444444444444444444444444444444444444444444444444");
        h.sourceCodeHash = bytes32(hex"5555555555555555555555555555555555555555555555555555555555555555");
        h.migrationId = bytes32(hex"6666666666666666666666666666666666666666666666666666666666666666");
        h.assetId = bytes32(hex"7777777777777777777777777777777777777777777777777777777777777777");
        h.destinationChainId = 31337;
        h.destinationContract = address(uint160(0x8888888888888888888888888888888888888888));
        h.entitlementKind = 1;
        h.decimals = 12;
        h.historicalHolderCount = 4;
        h.activeHolderCount = 3;
        h.totalUnits = 90;
    }

    function _entry(uint32 i) internal pure returns (MetorahManifestV1.Entry memory e) {
        e.leafIndex = i;
        if (i == 0) {
            e.historicalIndex = 0;
            e.sourceAccount = bytes32(hex"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
            e.beneficiary = address(uint160(0x1111111111111111111111111111111111111111));
            e.units = 10;
            e.bindingNonce = 1;
        } else if (i == 1) {
            e.historicalIndex = 2;
            e.sourceAccount = bytes32(hex"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
            e.beneficiary = address(uint160(0x2222222222222222222222222222222222222222));
            e.units = 30;
            e.bindingNonce = 2;
        } else if (i == 2) {
            e.historicalIndex = 3;
            e.sourceAccount = bytes32(hex"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc");
            e.beneficiary = address(uint160(0x3333333333333333333333333333333333333333));
            e.units = 50;
            e.bindingNonce = 1;
        } else {
            revert("invalid vector index");
        }
    }

    function testCanonicalHeaderPythonParity() public {
        assert(harness.hashHeader(_header()) == VECTOR_HEADER);
    }

    function testCanonicalLeafPythonParity() public {
        assert(harness.hashLeaf(VECTOR_HEADER, _entry(0)) == VECTOR_LEAF0);
        assert(harness.hashLeaf(VECTOR_HEADER, _entry(1)) == VECTOR_LEAF1);
        assert(harness.hashLeaf(VECTOR_HEADER, _entry(2)) == VECTOR_LEAF2);
    }

    function testCanonicalNodeAndManifestPythonParity() public {
        assert(harness.hashNode(VECTOR_LEAF0, VECTOR_LEAF1) == VECTOR_NODE01);
        assert(harness.hashNode(VECTOR_LEAF2, VECTOR_LEAF2) == VECTOR_NODE22);
        assert(harness.hashNode(VECTOR_NODE01, VECTOR_NODE22) == VECTOR_ROOT);
        assert(harness.hashManifest(VECTOR_HEADER, VECTOR_ROOT) == VECTOR_MANIFEST);
    }

    function testCanonicalDirectionSensitiveProofs() public {
        bytes32[] memory p0 = new bytes32[](2);
        p0[0] = VECTOR_LEAF1;
        p0[1] = VECTOR_NODE22;
        assert(harness.verify(VECTOR_HEADER, _entry(0), p0, VECTOR_ROOT, 3));
        bytes32[] memory p1 = new bytes32[](2);
        p1[0] = VECTOR_LEAF0;
        p1[1] = VECTOR_NODE22;
        assert(harness.verify(VECTOR_HEADER, _entry(1), p1, VECTOR_ROOT, 3));
        bytes32[] memory p2 = new bytes32[](2);
        p2[0] = VECTOR_LEAF2;
        p2[1] = VECTOR_NODE01;
        assert(harness.verify(VECTOR_HEADER, _entry(2), p2, VECTOR_ROOT, 3));
    }

    function testOddLeafMustBeSelfDuplicated() public {
        bytes32[] memory p = new bytes32[](2);
        p[0] = VECTOR_LEAF1; // invalid: odd index must duplicate itself
        p[1] = VECTOR_NODE01;
        assert(!harness.verify(VECTOR_HEADER, _entry(2), p, VECTOR_ROOT, 3));
    }

    function testPositionalProofCannotReverseSiblings() public {
        bytes32[] memory p = new bytes32[](2);
        p[0] = VECTOR_NODE22;
        p[1] = VECTOR_LEAF1;
        assert(!harness.verify(VECTOR_HEADER, _entry(0), p, VECTOR_ROOT, 3));
    }

    function testRejectIncorrectProofHeight() public {
        bytes32[] memory empty = new bytes32[](0);
        assert(!harness.verify(VECTOR_HEADER, _entry(0), empty, VECTOR_ROOT, 3));
        bytes32[] memory extra = new bytes32[](3);
        extra[0] = VECTOR_LEAF1; extra[1] = VECTOR_NODE22; extra[2] = VECTOR_ROOT;
        assert(!harness.verify(VECTOR_HEADER, _entry(0), extra, VECTOR_ROOT, 3));
    }

    function testCrossChainReplayChangesHeaderHash() public {
        MetorahManifestV1.Header memory h = _header();
        h.destinationChainId = 1;
        assert(harness.hashHeader(h) != VECTOR_HEADER);
        h = _header();h.sourceGenesis = bytes32(hex"9999999999999999999999999999999999999999999999999999999999999999");
        assert(harness.hashHeader(h) != VECTOR_HEADER);
        h = _header();h.destinationContract = address(uint160(0x9999999999999999999999999999999999999999));
        assert(harness.hashHeader(h) != VECTOR_HEADER);
        h = _header();h.migrationId = bytes32(hex"9999999999999999999999999999999999999999999999999999999999999999");
        assert(harness.hashHeader(h) != VECTOR_HEADER);
    }

    function testWrongBeneficiaryNonceOrAmountCannotUseProof() public {
        bytes32[] memory p = new bytes32[](2);
        p[0] = VECTOR_LEAF1;p[1] = VECTOR_NODE22;
        MetorahManifestV1.Entry memory e = _entry(0);
        e.beneficiary = address(uint160(0x9999999999999999999999999999999999999999));
        assert(!harness.verify(VECTOR_HEADER, e, p, VECTOR_ROOT, 3));
        e = _entry(0);e.bindingNonce = 2;
        assert(!harness.verify(VECTOR_HEADER, e, p, VECTOR_ROOT, 3));
        e = _entry(0);e.units = 11;
        assert(!harness.verify(VECTOR_HEADER, e, p, VECTOR_ROOT, 3));
    }

    function testRejectIncompleteHeader() public {
        MetorahManifestV1.Header memory h = _header();
        h.finalizedBlockHash = bytes32(0);
        vm.expectRevert();
        harness.hashHeader(h);
    }

    function testRejectUnboundEntitlement() public {
        MetorahManifestV1.Entry memory e = _entry(0);
        e.beneficiary = address(0);
        vm.expectRevert();
        harness.hashLeaf(VECTOR_HEADER, e);
    }

    function testRejectEmptyLeafCount() public {
        bytes32[] memory proof = new bytes32[](0);
        assert(!harness.verify(VECTOR_HEADER, _entry(0), proof, VECTOR_ROOT, 0));
    }

    function testOneLeafProofHasZeroSiblings() public {
        bytes32[] memory proof = new bytes32[](0);
        assert(harness.verify(VECTOR_HEADER, _entry(0), proof, VECTOR_LEAF0, 1));
    }
}
