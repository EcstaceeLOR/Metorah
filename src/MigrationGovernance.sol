// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {VerifiedTokenClaimLedger} from "./VerifiedTokenClaimLedger.sol";

/// @notice Role-separated, timelocked administration for one immutable migration ledger.
/// @dev The ledger must first nominate this contract as pending administrator, then this contract
/// accepts the handover. Configure the DEFAULT_ADMIN_ROLE as a multisig in production.
contract MigrationGovernance {
    bytes32 public constant DEFAULT_ADMIN_ROLE = bytes32(0);
    bytes32 public constant PROPOSER_ROLE = keccak256("PROPOSER_ROLE");
    bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");

    VerifiedTokenClaimLedger public immutable ledger;
    uint256 public immutable minDelay;
    mapping(bytes32 => mapping(address => bool)) private _roles;
    mapping(bytes32 => uint256) public queuedAt;
    uint256 public adminCount;

    event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender);
    event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender);
    event ActionScheduled(bytes32 indexed actionId, bytes32 indexed salt, uint256 eta, bytes data);
    event ActionCancelled(bytes32 indexed actionId, address indexed sender);
    event ActionExecuted(bytes32 indexed actionId, address indexed executor, bytes data);
    event EmergencyPauseTriggered(address indexed guardian);

    error Unauthorized();
    error InvalidConfiguration();
    error RoleAlreadySet();
    error RoleNotSet();
    error LastAdministrator();
    error ActionAlreadyQueued();
    error ActionNotQueued();
    error TimelockPending();
    error ExecutionFailed(bytes reason);

    constructor(address ledger_, uint256 minDelay_) {
        if (ledger_ == address(0) || minDelay_ == 0) revert InvalidConfiguration();
        ledger = VerifiedTokenClaimLedger(ledger_);
        minDelay = minDelay_;
        _roles[DEFAULT_ADMIN_ROLE][msg.sender] = true;
        adminCount = 1;
        emit RoleGranted(DEFAULT_ADMIN_ROLE, msg.sender, msg.sender);
    }

    modifier onlyRole(bytes32 role) {
        if (!_roles[role][msg.sender]) revert Unauthorized();
        _;
    }

    function hasRole(bytes32 role, address account) external view returns (bool) {
        return _roles[role][account];
    }

    function grantRole(bytes32 role, address account) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (account == address(0)) revert InvalidConfiguration();
        if (_roles[role][account]) revert RoleAlreadySet();
        _roles[role][account] = true;
        if (role == DEFAULT_ADMIN_ROLE) ++adminCount;
        emit RoleGranted(role, account, msg.sender);
    }

    function revokeRole(bytes32 role, address account) external onlyRole(DEFAULT_ADMIN_ROLE) {
        if (!_roles[role][account]) revert RoleNotSet();
        if (role == DEFAULT_ADMIN_ROLE) {
            if (adminCount <= 1) revert LastAdministrator();
            --adminCount;
        }
        _roles[role][account] = false;
        emit RoleRevoked(role, account, msg.sender);
    }

    /// @notice Call after the ledger administrator nominates this governance contract.
    function acceptLedgerAdministrator() external onlyRole(DEFAULT_ADMIN_ROLE) {
        ledger.acceptAdministrator();
    }

    /// @notice Guardian can stop claims immediately; unpausing must be scheduled through the timelock.
    function pauseImmediately() external onlyRole(GUARDIAN_ROLE) {
        ledger.pauseClaims();
        emit EmergencyPauseTriggered(msg.sender);
    }

    /// @notice Queue a ledger-admin call for execution after the configured delay.
    function schedule(bytes32 salt, bytes calldata data)
        external onlyRole(PROPOSER_ROLE) returns (bytes32 actionId, uint256 eta)
    {
        if (data.length < 4) revert InvalidConfiguration();
        actionId = hashAction(salt, data);
        if (queuedAt[actionId] != 0) revert ActionAlreadyQueued();
        eta = block.timestamp + minDelay;
        queuedAt[actionId] = eta;
        emit ActionScheduled(actionId, salt, eta, data);
    }

    function cancel(bytes32 salt, bytes calldata data) external returns (bytes32 actionId) {
        if (!_roles[GUARDIAN_ROLE][msg.sender] && !_roles[DEFAULT_ADMIN_ROLE][msg.sender]) revert Unauthorized();
        actionId = hashAction(salt, data);
        if (queuedAt[actionId] == 0) revert ActionNotQueued();
        delete queuedAt[actionId];
        emit ActionCancelled(actionId, msg.sender);
    }

    function execute(bytes32 salt, bytes calldata data)
        external returns (bytes memory result)
    {
        if (!_roles[EXECUTOR_ROLE][msg.sender] && !_roles[DEFAULT_ADMIN_ROLE][msg.sender]) revert Unauthorized();
        bytes32 actionId = hashAction(salt, data);
        uint256 eta = queuedAt[actionId];
        if (eta == 0) revert ActionNotQueued();
        if (block.timestamp < eta) revert TimelockPending();
        delete queuedAt[actionId];

        (bool ok, bytes memory returned) = address(ledger).call(data);
        if (!ok) revert ExecutionFailed(returned);
        emit ActionExecuted(actionId, msg.sender, data);
        return returned;
    }

    function hashAction(bytes32 salt, bytes calldata data) public view returns (bytes32) {
        return keccak256(abi.encode(address(ledger), salt, keccak256(data)));
    }
}
