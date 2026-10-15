// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Fail-closed destination ledger whose root requires an authorized ECDSA quorum and timelock.
/// @dev This verifies explicit attestations, NOT Portaldot proofs by itself. Signers must independently
///      verify the evidence off-chain. Credits are accounting entries; no assets are held or transferred.
contract VerifiedEvidenceLedger {
    bytes32 private constant ATTESTATION_TYPEHASH = keccak256(
        "EvidenceAttestation(bytes32 migrationId,bytes32 root,bytes32 manifestHash,bytes32 freezeHash,uint256 totalAllocation,uint256 chainId,address ledger,uint64 activationTime)"
    );
    bytes32 private constant DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 private constant NAME_HASH = keccak256("Metorah Verified Evidence Ledger");
    bytes32 private constant VERSION_HASH = keccak256("1");

    bytes32 public immutable migrationId;
    bytes32 public immutable sourceFreezeEvidenceHash;
    uint256 public immutable totalAllocation;
    uint64 public immutable reviewDelay;
    uint8 public immutable quorum;
    address public immutable administrator;
    uint64 public activationTime;
    bytes32 public merkleRoot;
    bytes32 public manifestHash;
    bool public proposed;
    bool public activated;
    uint256 public totalClaimed;
    mapping(address => bool) public authorizedSigner;
    mapping(uint256 => bool) public claimed;
    mapping(address => uint256) public credits;

    event EvidenceProposed(bytes32 indexed root, bytes32 indexed manifestHash, uint64 activationTime);
    event EvidenceActivated(bytes32 indexed root, bytes32 indexed manifestHash);
    event EntitlementClaimed(uint256 indexed index, bytes32 indexed sourceAccountId, address indexed beneficiary, uint256 amount);

    error Unauthorized();
    error InvalidConfiguration();
    error InvalidEvidence();
    error InvalidSignatures();
    error ReviewPending();
    error AlreadyActivated();
    error NotActivated();
    error InvalidClaim();

    constructor(
        bytes32 migrationId_,
        bytes32 freezeHash_,
        uint256 totalAllocation_,
        uint64 reviewDelay_,
        uint8 quorum_,
        address[] memory signers
    ) {
        if (migrationId_ == bytes32(0) || freezeHash_ == bytes32(0) || totalAllocation_ == 0 ||
            quorum_ == 0 || signers.length < quorum_ || reviewDelay_ == 0) revert InvalidConfiguration();
        migrationId = migrationId_;
        sourceFreezeEvidenceHash = freezeHash_;
        totalAllocation = totalAllocation_;
        reviewDelay = reviewDelay_;
        quorum = quorum_;
        administrator = msg.sender;
        for (uint256 i; i < signers.length; ++i) {
            address signer = signers[i];
            if (signer == address(0) || authorizedSigner[signer]) revert InvalidConfiguration();
            authorizedSigner[signer] = true;
        }
    }

    function proposeEvidence(
        bytes32 root,
        bytes32 manifest,
        uint64 activationTime_,
        bytes[] calldata signatures
    ) external {
        if (activated) revert AlreadyActivated();
        if (proposed || root == bytes32(0) || manifest == bytes32(0) ||
            activationTime_ < block.timestamp + reviewDelay) revert InvalidEvidence();

        bytes32 digest = _attestationDigest(root, manifest, activationTime_);
        address previous;
        uint256 valid;
        for (uint256 i; i < signatures.length; ++i) {
            address signer = _recover(digest, signatures[i]);
            if (!authorizedSigner[signer] || signer <= previous) revert InvalidSignatures();
            previous = signer;
            ++valid;
        }
        if (valid < quorum) revert InvalidSignatures();

        proposed = true;
        merkleRoot = root;
        manifestHash = manifest;
        activationTime = activationTime_;
        emit EvidenceProposed(root, manifest, activationTime_);
    }

    function activate() external {
        if (!proposed || activated) revert InvalidEvidence();
        if (block.timestamp < activationTime) revert ReviewPending();
        activated = true;
        emit EvidenceActivated(merkleRoot, manifestHash);
    }

    function leafHash(uint256 index, bytes32 sourceAccountId, address beneficiary, uint256 amount)
        public view returns (bytes32)
    {
        return keccak256(abi.encode(
            bytes32("METORAH_VERIFIED_LEAF_V1"), block.chainid, address(this),
            migrationId, index, sourceAccountId, beneficiary, amount
        ));
    }

    function claim(uint256 index, bytes32 sourceAccountId, uint256 amount, bytes32[] calldata proof) external {
        if (!activated) revert NotActivated();
        if (claimed[index] || amount == 0 || totalClaimed + amount > totalAllocation) revert InvalidClaim();
        bytes32 computed = leafHash(index, sourceAccountId, msg.sender, amount);
        for (uint256 i; i < proof.length; ++i) {
            bytes32 sibling = proof[i];
            computed = computed < sibling
                ? keccak256(abi.encodePacked(computed, sibling))
                : keccak256(abi.encodePacked(sibling, computed));
        }
        if (computed != merkleRoot) revert InvalidClaim();
        claimed[index] = true;
        totalClaimed += amount;
        credits[msg.sender] += amount;
        emit EntitlementClaimed(index, sourceAccountId, msg.sender, amount);
    }

    function attestationDigest(bytes32 root, bytes32 manifest, uint64 activationTime_)
        external view returns (bytes32)
    {
        return _attestationDigest(root, manifest, activationTime_);
    }

    function _attestationDigest(bytes32 root, bytes32 manifest, uint64 activationTime_)
        internal view returns (bytes32)
    {
        bytes32 structHash = keccak256(abi.encode(
            ATTESTATION_TYPEHASH, migrationId, root, manifest, sourceFreezeEvidenceHash,
            totalAllocation, block.chainid, address(this), activationTime_
        ));
        bytes32 domain = keccak256(abi.encode(
            DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, block.chainid, address(this)
        ));
        return keccak256(abi.encodePacked("\x19\x01", domain, structHash));
    }

    function _recover(bytes32 digest, bytes calldata signature) internal pure returns (address signer) {
        if (signature.length != 65) return address(0);
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        if (uint256(s) > 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0 || (v != 27 && v != 28)) {
            return address(0);
        }
        signer = ecrecover(digest, v, r, s);
    }
}
