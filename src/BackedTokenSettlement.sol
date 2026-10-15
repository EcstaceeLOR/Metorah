// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Exact-transfer ERC-20 escrow adapter for a single migration allocation.
/// @dev Only the configured settlement controller can release funds. Fee-on-transfer and rebasing
/// tokens are unsupported. The controller must enforce verified claims and beneficiary bindings.
interface IERC20Settlement {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract BackedTokenSettlement {
    IERC20Settlement public immutable token;
    address public immutable controller;
    address public immutable funder;
    uint256 public immutable allocationCap;
    uint256 public totalFunded;
    uint256 public totalSettled;
    bool private _settlementEntered;
    mapping(bytes32 => bool) public settledClaim;

    struct AccountingSnapshot {
        uint256 authorizedAllocation;
        uint256 totalFunded;
        uint256 totalSettled;
        uint256 escrowTokenBalance;
        uint256 remainingAuthorizedAllocation;
        uint256 remainingFundedLiability;
        uint256 unfundedAuthorizedAllocation;
        uint256 availableBacking;
        uint256 surplusTokenBalance;
    }

    event Funded(address indexed funder, uint256 amount, uint256 totalFunded);
    event Settled(bytes32 indexed claimId, address indexed beneficiary, uint256 amount, uint256 totalSettled);
    event SettlementAccountingUpdated(
        uint256 authorizedAllocation,
        uint256 totalFunded,
        uint256 totalSettled,
        uint256 escrowTokenBalance,
        uint256 remainingFundedLiability,
        uint256 unfundedAuthorizedAllocation
    );

    error Unauthorized();
    error InvalidConfiguration();
    error InvalidAmount();
    error UnsupportedTokenBehavior();
    error InsufficientBacking();
    error DuplicateSettlement();
    error TransferFailed();
    error ReentrantCall();

    modifier nonReentrant() {
        if (_settlementEntered) revert ReentrantCall();
        _settlementEntered = true;
        _;
        _settlementEntered = false;
    }

    constructor(address token_, address controller_, address funder_, uint256 allocationCap_) {
        if (token_ == address(0) || controller_ == address(0) || funder_ == address(0) || allocationCap_ == 0) {
            revert InvalidConfiguration();
        }
        token = IERC20Settlement(token_);
        controller = controller_;
        funder = funder_;
        allocationCap = allocationCap_;
    }

    function fund(uint256 amount) external {
        if (msg.sender != funder) revert Unauthorized();
        if (amount == 0 || totalFunded + amount > allocationCap) revert InvalidAmount();
        uint256 beforeBalance = token.balanceOf(address(this));
        _safeTransferFrom(funder, address(this), amount);
        uint256 afterBalance = token.balanceOf(address(this));
        if (afterBalance < beforeBalance || afterBalance - beforeBalance != amount) revert UnsupportedTokenBehavior();
        totalFunded += amount;
        emit Funded(funder, amount, totalFunded);
        _emitAccountingUpdate(afterBalance);
    }

    function settle(bytes32 claimId, address beneficiary, uint256 amount) external nonReentrant {
        if (msg.sender != controller) revert Unauthorized();
        if (claimId == bytes32(0) || beneficiary == address(0) || amount == 0) revert InvalidAmount();
        if (settledClaim[claimId]) revert DuplicateSettlement();
        if (totalSettled + amount > totalFunded || totalSettled + amount > allocationCap) revert InsufficientBacking();

        uint256 beforeBalance = token.balanceOf(address(this));
        uint256 beneficiaryBefore = token.balanceOf(beneficiary);
        settledClaim[claimId] = true;
        totalSettled += amount;
        _safeTransfer(beneficiary, amount);
        uint256 afterBalance = token.balanceOf(address(this));
        uint256 beneficiaryAfter = token.balanceOf(beneficiary);
        if (afterBalance > beforeBalance || beforeBalance - afterBalance != amount ||
            beneficiaryAfter < beneficiaryBefore || beneficiaryAfter - beneficiaryBefore != amount) {
            revert UnsupportedTokenBehavior();
        }
        emit Settled(claimId, beneficiary, amount, totalSettled);
        _emitAccountingUpdate(afterBalance);
    }

    function availableBacking() external view returns (uint256) {
        uint256 balance = token.balanceOf(address(this));
        return balance < totalFunded - totalSettled ? balance : totalFunded - totalSettled;
    }

    /// @notice Remaining portion of the authorized cap not yet settled, whether funded or not.
    function remainingAuthorizedAllocation() external view returns (uint256) {
        return allocationCap - totalSettled;
    }

    /// @notice Authorized amount not yet physically deposited, measured against cumulative funding.
    function unfundedAuthorizedAllocation() external view returns (uint256) {
        return allocationCap - totalFunded;
    }

    /// @notice Funded amount not yet settled; this is an accounting liability, not proof of token solvency.
    function remainingFundedLiability() external view returns (uint256) {
        return totalFunded - totalSettled;
    }

    function escrowTokenBalance() external view returns (uint256) {
        return token.balanceOf(address(this));
    }

    /// @notice Snapshot separates authorized cap, deposited funds, paid claims and actual token balance.
    function accountingSnapshot() external view returns (AccountingSnapshot memory snapshot) {
        uint256 balance = token.balanceOf(address(this));
        uint256 liability = totalFunded - totalSettled;
        snapshot = AccountingSnapshot({
            authorizedAllocation: allocationCap,
            totalFunded: totalFunded,
            totalSettled: totalSettled,
            escrowTokenBalance: balance,
            remainingAuthorizedAllocation: allocationCap - totalSettled,
            remainingFundedLiability: liability,
            unfundedAuthorizedAllocation: allocationCap - totalFunded,
            availableBacking: balance < liability ? balance : liability,
            surplusTokenBalance: balance > liability ? balance - liability : 0
        });
    }

    function _emitAccountingUpdate(uint256 balance) private {
        emit SettlementAccountingUpdated(
            allocationCap,
            totalFunded,
            totalSettled,
            balance,
            totalFunded - totalSettled,
            allocationCap - totalFunded
        );
    }

    function _safeTransfer(address to, uint256 amount) private {
        (bool ok, bytes memory data) = address(token).call(
            abi.encodeWithSelector(IERC20Settlement.transfer.selector, to, amount)
        );
        if (!ok || (data.length != 0 && !abi.decode(data, (bool)))) revert TransferFailed();
    }

    function _safeTransferFrom(address from, address to, uint256 amount) private {
        (bool ok, bytes memory data) = address(token).call(
            abi.encodeWithSelector(IERC20Settlement.transferFrom.selector, from, to, amount)
        );
        if (!ok || (data.length != 0 && !abi.decode(data, (bool)))) revert TransferFailed();
    }
}
