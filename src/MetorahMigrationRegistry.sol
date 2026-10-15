// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {MetorahClaimLedger} from "./MetorahClaimLedger.sol";

/// @notice Deterministic registry for isolated, ACCOUNTING-ONLY migration ledgers.
/// @dev The registry owner is a privileged coordinator; this does not verify
///      source finality, holder coverage, beneficiary consent, or backing assets.
contract MetorahMigrationRegistry {
    bytes32 public constant ID_DOMAIN = keccak256("METORAH_MIGRATION_REGISTRY_V1");

    struct Domain {
        bytes32 sourceGenesis;
        bytes32 sourceContract;
        uint256 destinationChainId;
        bytes32 mode;
        uint32 manifestVersion;
        bytes32 assetId;
    }

    address public immutable owner;
    mapping(bytes32 => address) public ledgerOf;
    mapping(address => bytes32) public migrationOf;

    event MigrationCreated(
        bytes32 indexed migrationId,
        address indexed ledger,
        address indexed proposedAdministrator,
        bytes32 sourceGenesis,
        bytes32 sourceContract,
        uint256 destinationChainId,
        bytes32 mode,
        uint32 manifestVersion,
        bytes32 assetId,
        bytes32 sourceFreezeEvidenceHash,
        uint256 totalAllocation
    );

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not registry owner");
        _;
    }

    function _validate(Domain memory domain) internal view {
        require(domain.sourceGenesis != bytes32(0), "missing genesis");
        require(domain.sourceContract != bytes32(0), "missing source contract");
        require(domain.destinationChainId != 0 && domain.destinationChainId == block.chainid, "wrong destination chain");
        require(domain.mode != bytes32(0), "missing mode");
        require(domain.manifestVersion != 0, "missing manifest version");
        require(domain.assetId != bytes32(0), "missing asset");
    }

    /// @notice Canonical typed ABI-encoded ID. Unique for distinct domain tuples,
    ///         apart from the inherent cryptographic collision assumption.
    function migrationId(Domain calldata domain) public view returns (bytes32) {
        _validate(domain);
        return keccak256(abi.encode(
            ID_DOMAIN, address(this),
            domain.sourceGenesis,
            domain.sourceContract,
            domain.destinationChainId,
            domain.mode,
            domain.manifestVersion,
            domain.assetId
        ));
    }

    function _initCodeHash(
        bytes32 id,
        bytes32 freezeEvidence,
        uint256 totalAllocation
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(
            type(MetorahClaimLedger).creationCode,
            abi.encode(id, freezeEvidence, totalAllocation)
        ));
    }

    /// @notice Predict byte-for-byte CREATE2 address before creation.
    /// @dev Prediction includes migration domain, evidence commitment and cap.
    function predictLedger(
        Domain calldata domain,
        bytes32 freezeEvidence,
        uint256 totalAllocation
    ) external view returns (address) {
        bytes32 id = migrationId(domain);
        require(freezeEvidence != bytes32(0) && totalAllocation > 0, "invalid evidence or cap");
        bytes32 h = keccak256(abi.encodePacked(
            bytes1(0xff), address(this), id, _initCodeHash(id, freezeEvidence, totalAllocation)
        ));
        return address(uint160(uint256(h)));
    }

    /// @notice Creates a ledger with a pending administrator who must accept.
    /// @dev Only the operator may reserve a migration domain; avoids attacker
    ///      front-running/occupying a domain with a fabricated freeze root.
    function createMigration(
        Domain calldata domain,
        bytes32 freezeEvidence,
        uint256 totalAllocation,
        address proposedAdministrator
    ) external onlyOwner returns (bytes32 id, address ledgerAddress) {
        id = migrationId(domain);
        require(ledgerOf[id] == address(0), "migration already exists");
        require(freezeEvidence != bytes32(0) && totalAllocation > 0, "invalid evidence or cap");
        require(proposedAdministrator != address(0) && proposedAdministrator != address(this), "invalid administrator");
        // CREATE2 salt is the unique domain-separated migration identifier.
        MetorahClaimLedger ledger = new MetorahClaimLedger{salt: id}(id, freezeEvidence, totalAllocation);
        ledgerAddress = address(ledger);
        require(ledgerAddress != address(0) && ledgerAddress.code.length > 0, "deployment failed");
        ledger.proposeAdministrator(proposedAdministrator);
        ledgerOf[id] = ledgerAddress;
        migrationOf[ledgerAddress] = id;
        emit MigrationCreated(
            id, ledgerAddress, proposedAdministrator,
            domain.sourceGenesis, domain.sourceContract,
            domain.destinationChainId, domain.mode, domain.manifestVersion,
            domain.assetId, freezeEvidence, totalAllocation
        );
    }
}
