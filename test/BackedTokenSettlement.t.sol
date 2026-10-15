// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {BackedTokenSettlement} from "../src/BackedTokenSettlement.sol";

contract MockExactToken {
    mapping(address => uint256) public balanceOf;
    bool public feeMode;
    function mint(address to, uint256 amount) external { balanceOf[to] += amount; }
    function setFeeMode(bool value) external { feeMode = value; }
    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "balance");
        balanceOf[msg.sender] -= amount;
        uint256 received = feeMode ? amount - 1 : amount;
        balanceOf[to] += received;
        return true;
    }
    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(balanceOf[from] >= amount, "balance");
        balanceOf[from] -= amount;
        uint256 received = feeMode ? amount - 1 : amount;
        balanceOf[to] += received;
        return true;
    }
}

contract BackedTokenSettlementTest {
    MockExactToken token;
    BackedTokenSettlement settlement;
    address beneficiary = address(0xBEEF);
    function setUp() public {
        token = new MockExactToken();
        settlement = new BackedTokenSettlement(address(token), address(this), address(this), 1000);
        token.mint(address(this), 1000);
    }
    function testFundAndSettlePreservesExactBalances() public {
        settlement.fund(500);
        require(token.balanceOf(address(settlement)) == 500, "escrow funding");
        settlement.settle(keccak256("claim-1"), beneficiary, 200);
        require(token.balanceOf(beneficiary) == 200, "beneficiary payout");
        require(settlement.totalFunded() == 500, "funded accounting");
        require(settlement.totalSettled() == 200, "settled accounting");
        require(settlement.availableBacking() == 300, "backing");
    }
    function testRejectsOverAllocationAndDuplicateClaim() public {
        settlement.fund(500);
        (bool ok,) = address(settlement).call(abi.encodeCall(settlement.settle, (keccak256("claim-1"), beneficiary, 300)));
        require(ok, "first settlement");
        (ok,) = address(settlement).call(abi.encodeCall(settlement.settle, (keccak256("claim-1"), beneficiary, 1)));
        require(!ok, "duplicate accepted");
        (ok,) = address(settlement).call(abi.encodeCall(settlement.settle, (keccak256("claim-2"), beneficiary, 201)));
        require(!ok, "underfunded settlement accepted");
    }
    function testRejectsFeeOnTransferFunding() public {
        token.setFeeMode(true);
        (bool ok,) = address(settlement).call(abi.encodeCall(settlement.fund, (100)));
        require(!ok, "fee-on-transfer token accepted");
    }
    function testRejectsFeeOnTransferPayout() public {
        settlement.fund(100);
        token.setFeeMode(true);
        (bool ok,) = address(settlement).call(abi.encodeCall(settlement.settle, (keccak256("claim-1"), beneficiary, 50)));
        require(!ok, "fee-on-transfer payout accepted");
        require(settlement.totalSettled() == 0, "state not reverted");
    }
}
