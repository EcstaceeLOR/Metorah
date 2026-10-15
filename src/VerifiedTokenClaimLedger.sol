// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {SourceAuthorizedBindings} from "./SourceAuthorizedBindings.sol";
import {BackedTokenSettlement} from "./BackedTokenSettlement.sol";

/// @notice Quorum-approved, delayed migration claims that pay real escrowed ERC-20 tokens.
/// @dev Attestations are only as trustworthy as the signers' off-chain evidence verification.
/// Amounts are denominated in the token's smallest units; no decimal conversion is performed here.
contract VerifiedTokenClaimLedger {
    bytes32 private constant ATTESTATION_TYPEHASH = keccak256(
        "EvidenceAttestation(bytes32 migrationId,bytes32 root,bytes32 manifestHash,bytes32 freezeHash,uint256 totalAllocation,uint256 chainId,address ledger,uint64 activationTime)"
    );
    bytes32 private constant DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 private constant NAME_HASH = keccak256("Metorah Verified Token Claim Ledger");
    bytes32 private constant VERSION_HASH = keccak256("1");

    bytes32 public immutable migrationId;
    bytes32 public immutable sourceFreezeEvidenceHash;
    uint256 public immutable totalAllocation;
    uint64 public immutable reviewDelay;
    uint8 public immutable quorum;
    address public administrator;
    address public pendingAdministrator;
    SourceAuthorizedBindings public immutable bindings;
    BackedTokenSettlement public settlement;

    uint64 public activationTime;
    bytes32 public merkleRoot;
    bytes32 public manifestHash;
    bool public proposed;
    bool public activated;
    bool public paused;
    uint256 public totalClaimed;
    uint256 public constant MAX_PROOF_LENGTH = 64;
    bool private _claimEntered;
    mapping(address => bool) public authorizedSigner;
    mapping(uint256 => bool) public claimed;

    struct ClaimReceipt {
        bytes32 sourceAccountId;
        address beneficiary;
        uint256 amount;
        bytes32 claimId;
        uint256 settledAt;
    }

    struct MigrationStatus {
        bytes32 migrationId;
        bytes32 sourceFreezeEvidenceHash;
        bytes32 merkleRoot;
        bytes32 manifestHash;
        uint256 totalAllocation;
        uint256 totalClaimed;
        uint64 activationTime;
        bool proposed;
        bool activated;
        bool paused;
        uint256 totalFunded;
        uint256 totalSettled;
        uint256 escrowTokenBalance;
        uint256 remainingFundedLiability;
        uint256 unfundedAuthorizedAllocation;
        uint256 availableBacking;
    }

    mapping(uint256 => ClaimReceipt) public claimReceipts;

    event EvidenceProposed(bytes32 indexed root, bytes32 indexed manifestHash, uint64 activationTime);
    event EvidenceActivated(bytes32 indexed root, bytes32 indexed manifestHash);
    event TokenClaimSettled(uint256 indexed index, bytes32 indexed sourceAccountId, address indexed beneficiary, uint256 amount, bytes32 claimId);
    event SettlementConfigured(address indexed settlement);
    event ClaimsPaused(address indexed account);
    event ClaimsUnpaused(address indexed account);
    event AdministratorTransferStarted(address indexed currentAdministrator, address indexed pendingAdministrator);
    event AdministratorTransferred(address indexed previousAdministrator, address indexed newAdministrator);
    event EvidenceCancelled(bytes32 indexed previousRoot, bytes32 indexed previousManifestHash);
    event SurplusRecovered(address indexed recipient, uint256 amount);
    event ClaimReceiptRecorded(
        uint256 indexed index,
        bytes32 indexed claimId,
        address indexed beneficiary,
        uint256 amount,
        uint256 totalClaimed,
        uint256 totalFunded,
        uint256 totalSettled,
        uint256 settledAt
    );

    error Unauthorized();
    error InvalidConfiguration();
    error InvalidEvidence();
    error InvalidSignatures();
    error ReviewPending();
    error NotActivated();
    error InvalidClaim();
    error SettlementAlreadyConfigured();
    error ReentrantCall();
    error ProofTooLong();
    error ClaimsArePaused();
    error InvalidAdministrator();

    modifier nonReentrant() {
        if (_claimEntered) revert ReentrantCall();
        _claimEntered = true;
        _;
        _claimEntered = false;
    }

    constructor(
        bytes32 migrationId_,
        bytes32 freezeHash_,
        uint256 totalAllocation_,
        uint64 reviewDelay_,
        uint8 quorum_,
        address[] memory signers,
        address bindings_
    ) {
        if (
            migrationId_ == bytes32(0) || freezeHash_ == bytes32(0) || totalAllocation_ == 0 ||
            reviewDelay_ == 0 || quorum_ == 0 || signers.length < quorum_ || bindings_ == address(0)
        ) revert InvalidConfiguration();
        if (SourceAuthorizedBindings(bindings_).migrationId() != migrationId_) revert InvalidConfiguration();

        migrationId = migrationId_;
        sourceFreezeEvidenceHash = freezeHash_;
        totalAllocation = totalAllocation_;
        reviewDelay = reviewDelay_;
        quorum = quorum_;
        administrator = msg.sender;
        bindings = SourceAuthorizedBindings(bindings_);

        for (uint256 i; i < signers.length; ++i) {
            address signer = signers[i];
            if (signer == address(0) || authorizedSigner[signer]) revert InvalidConfiguration();
            authorizedSigner[signer] = true;
        }
    }

    /// @notice Two-step admin handover prevents accidental transfer to an unusable address.
    function proposeAdministrator(address nextAdministrator) external {
        if (msg.sender != administrator) revert Unauthorized();
        if (nextAdministrator == address(0) || nextAdministrator == administrator) revert InvalidAdministrator();
        pendingAdministrator = nextAdministrator;
        emit AdministratorTransferStarted(administrator, nextAdministrator);
    }

    function acceptAdministrator() external {
        if (msg.sender != pendingAdministrator || msg.sender == address(0)) revert Unauthorized();
        address previous = administrator;
        administrator = msg.sender;
        pendingAdministrator = address(0);
        emit AdministratorTransferred(previous, msg.sender);
    }

    /// @notice Root correction is permitted only before activation; cancellation clears the reviewed root.
    function cancelEvidence() external {
        if (msg.sender != administrator) revert Unauthorized();
        if (!proposed || activated) revert InvalidEvidence();
        bytes32 previousRoot = merkleRoot;
        bytes32 previousManifest = manifestHash;
        proposed = false;
        merkleRoot = bytes32(0);
        manifestHash = bytes32(0);
        activationTime = 0;
        emit EvidenceCancelled(previousRoot, previousManifest);
    }

    /// @notice Recover only tokens exceeding all remaining funded holder liabilities.
    function recoverSurplus(address recipient, uint256 amount) external {
        if (msg.sender != administrator) revert Unauthorized();
        if (address(settlement) == address(0)) revert InvalidConfiguration();
        settlement.recoverSurplus(recipient, amount);
        emit SurplusRecovered(recipient, amount);
    }

    /// @notice One-time wiring after deploying this ledger, with this ledger as the escrow controller.
    /// Must happen before evidence is proposed; this prevents switching payout assets after review starts.
    function configureSettlement(address settlement_) external {
        if (msg.sender != administrator) revert Unauthorized();
        if (proposed || activated || address(settlement) != address(0)) revert SettlementAlreadyConfigured();
        if (settlement_ == address(0)) revert InvalidConfiguration();
        BackedTokenSettlement candidate = BackedTokenSettlement(settlement_);
        if (candidate.controller() != address(this) || candidate.allocationCap() < totalAllocation) {
            revert InvalidConfiguration();
        }
        settlement = candidate;
        emit SettlementConfigured(settlement_);
    }

    function proposeEvidence(bytes32 root, bytes32 manifest, uint64 activationTime_, bytes[] calldata signatures) external {
        if (msg.sender != administrator) revert Unauthorized();
        if (address(settlement) == address(0)) revert InvalidConfiguration();
        if (activated || proposed || root == bytes32(0) || manifest == bytes32(0) ||
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

    /// @notice Emergency brake. Governance hardening and multisig controls are tracked separately.
    function pauseClaims() external {
        if (msg.sender != administrator) revert Unauthorized();
        if (paused) revert InvalidConfiguration();
        paused = true;
        emit ClaimsPaused(msg.sender);
    }

    function unpauseClaims() external {
        if (msg.sender != administrator) revert Unauthorized();
        if (!paused) revert InvalidConfiguration();
        paused = false;
        emit ClaimsUnpaused(msg.sender);
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
            bytes32("METORAH_VERIFIED_TOKEN_LEAF_V1"), block.chainid, address(this),
            migrationId, index, sourceAccountId, beneficiary, amount
        ));
    }

    /// @notice Verify the approved entitlement and source binding, then transfer actual escrowed tokens.
    function claim(uint256 index, bytes32 sourceAccountId, uint256 amount, bytes32[] calldata proof) external nonReentrant {
        if (!activated) revert NotActivated();
        if (paused) revert ClaimsArePaused();
        if (address(settlement) == address(0) || claimed[index] || sourceAccountId == bytes32(0) ||
            amount == 0 || totalClaimed + amount > totalAllocation) revert InvalidClaim();

        address beneficiary = bindings.beneficiaryOf(sourceAccountId);
        if (!bindings.verifyBinding(sourceAccountId, beneficiary) || beneficiary != msg.sender) revert InvalidClaim();

        if (proof.length > MAX_PROOF_LENGTH) revert ProofTooLong();
        bytes32 computed = leafHash(index, sourceAccountId, beneficiary, amount);
        for (uint256 i; i < proof.length; ++i) {
            bytes32 sibling = proof[i];
            computed = computed < sibling
                ? keccak256(abi.encodePacked(computed, sibling))
                : keccak256(abi.encodePacked(sibling, computed));
        }
        if (computed != merkleRoot) revert InvalidClaim();

        bytes32 claimId = keccak256(abi.encode(migrationId, index, sourceAccountId));
        claimed[index] = true;
        totalClaimed += amount;
        settlement.settle(claimId, beneficiary, amount);
        uint256 settledAt = block.timestamp;
        claimReceipts[index] = ClaimReceipt({
            sourceAccountId: sourceAccountId,
            beneficiary: beneficiary,
            amount: amount,
            claimId: claimId,
            settledAt: settledAt
        });
        emit TokenClaimSettled(index, sourceAccountId, beneficiary, amount, claimId);
        emit ClaimReceiptRecorded(
            index, claimId, beneficiary, amount, totalClaimed,
            settlement.totalFunded(), settlement.totalSettled(), settledAt
        );
    }

    /// @notice On-chain migration/accounting status; remains available without an indexer or backend.
    function migrationStatus() external view returns (MigrationStatus memory status) {
        status.migrationId = migrationId;
        status.sourceFreezeEvidenceHash = sourceFreezeEvidenceHash;
        status.merkleRoot = merkleRoot;
        status.manifestHash = manifestHash;
        status.totalAllocation = totalAllocation;
        status.totalClaimed = totalClaimed;
        status.activationTime = activationTime;
        status.proposed = proposed;
        status.activated = activated;
        status.paused = paused;
        if (address(settlement) != address(0)) {
            BackedTokenSettlement.AccountingSnapshot memory snapshot = settlement.accountingSnapshot();
            status.totalFunded = snapshot.totalFunded;
            status.totalSettled = snapshot.totalSettled;
            status.escrowTokenBalance = snapshot.escrowTokenBalance;
            status.remainingFundedLiability = snapshot.remainingFundedLiability;
            status.unfundedAuthorizedAllocation = snapshot.unfundedAuthorizedAllocation;
            status.availableBacking = snapshot.availableBacking;
        }
    }

    function attestationDigest(bytes32 root, bytes32 manifest, uint64 activationTime_) external view returns (bytes32) {
        return _attestationDigest(root, manifest, activationTime_);
    }

    function _attestationDigest(bytes32 root, bytes32 manifest, uint64 activationTime_) internal view returns (bytes32) {
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
        if (
            uint256(s) > 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0 ||
            (v != 27 && v != 28)
        ) return address(0);
        signer = ecrecover(digest, v, r, s);
    }
}
