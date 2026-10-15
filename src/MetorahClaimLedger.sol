// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title MetorahClaimLedger
 * @notice Target-side entitlement ledger for one migration, NOT a complete or trustless bridge.
 * @dev Owner/administrator is trusted to publish an honest Merkle root and source freeze evidence.
 *      Local claim proofs verify inclusion in that root, not authenticity of source-chain state.
 *      This ledger records migrated credits; it DOES NOT mint, transfer, or redeem actual tokens.
 */
contract MetorahClaimLedger {
    bytes32 public immutable migrationId;
    bytes32 public immutable sourceFreezeEvidenceHash;
    uint256 public immutable totalAllocation;
    address public administrator;
    address public pendingAdministrator;
    bytes32 public merkleRoot;
    bytes32 public manifestHash;
    bool public committed;
    uint256 public totalClaimed;
    mapping(uint256 => bool) public claimed;
    mapping(address => uint256) public credits;

    event AdministratorProposed(address indexed previousAdministrator, address indexed proposedAdministrator);
    event AdministratorAccepted(address indexed previousAdministrator, address indexed newAdministrator);

    /// @notice Propose a replacement authority. This alone confers no rights.
    function proposeAdministrator(address replacement) external {
        require(msg.sender == administrator, "not administrator");
        require(!committed, "root already committed");
        require(replacement != address(0) && replacement != administrator, "invalid administrator");
        pendingAdministrator = replacement;
        emit AdministratorProposed(administrator, replacement);
    }

    /// @notice Two-step acceptance protects deployments from assigning wrong keys.
    function acceptAdministrator() external {
        require(msg.sender == pendingAdministrator && pendingAdministrator != address(0), "not proposed administrator");
        require(!committed, "root already committed");
        address previous = administrator;
        administrator = msg.sender;
        pendingAdministrator = address(0);
        emit AdministratorAccepted(previous, msg.sender);
    }

    event RootCommitted(bytes32 indexed migrationId, bytes32 indexed merkleRoot, bytes32 manifestHash);
    event EntitlementClaimed(uint256 indexed index, bytes32 indexed sourceAccountId, address indexed beneficiary, uint256 amount);

    constructor(bytes32 _migrationId, bytes32 _sourceFreezeEvidenceHash, uint256 _totalAllocation) {
        require(_migrationId != bytes32(0) && _sourceFreezeEvidenceHash != bytes32(0), "missing evidence");
        require(_totalAllocation > 0, "empty allocation");
        migrationId = _migrationId;
        sourceFreezeEvidenceHash = _sourceFreezeEvidenceHash;
        totalAllocation = _totalAllocation;
        administrator = msg.sender;
    }

    /** @notice One-time privileged publication. This is NOT source-chain proof verification. */
    function commitRoot(bytes32 root, bytes32 manifest) external {
        require(msg.sender == administrator, "not administrator");
        require(!committed && root != bytes32(0) && manifest != bytes32(0), "invalid root");
        committed = true;
        merkleRoot = root;
        manifestHash = manifest;
        emit RootCommitted(migrationId, root, manifest);
    }

    /** @dev leaf binds source ID, destination address, index, migration ID, chain ID and this contract. */
    function leafHash(uint256 index, bytes32 sourceAccountId, address beneficiary, uint256 amount) public view returns (bytes32) {
        return keccak256(abi.encode(
            bytes32("STATELIFT_LEAF_V1"), block.chainid, address(this), migrationId, index, sourceAccountId, beneficiary, amount
        ));
    }

    function claim(uint256 index, bytes32 sourceAccountId, uint256 amount, bytes32[] calldata proof) external {
        require(committed, "not committed");
        require(!claimed[index], "already claimed");
        require(amount > 0 && totalClaimed + amount <= totalAllocation, "allocation exceeded");
        bytes32 computed = leafHash(index, sourceAccountId, msg.sender, amount);
        for (uint256 i = 0; i < proof.length; ++i) {
            bytes32 sibling = proof[i];
            computed = computed < sibling
                ? keccak256(abi.encodePacked(computed, sibling))
                : keccak256(abi.encodePacked(sibling, computed));
        }
        require(computed == merkleRoot, "invalid proof");
        claimed[index] = true;
        totalClaimed += amount;
        credits[msg.sender] += amount;
        emit EntitlementClaimed(index, sourceAccountId, msg.sender, amount);
    }
}
