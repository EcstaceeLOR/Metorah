// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {SourceAuthorizedBindings} from "../src/SourceAuthorizedBindings.sol";
import {BackedTokenSettlement} from "../src/BackedTokenSettlement.sol";
import {VerifiedTokenClaimLedger} from "../src/VerifiedTokenClaimLedger.sol";
import {MigrationGovernance} from "../src/MigrationGovernance.sol";

interface VmMigrationGovernance {
    function addr(uint256 privateKey) external returns (address);
    function sign(uint256 privateKey, bytes32 digest) external returns (uint8, bytes32, bytes32);
    function warp(uint256 timestamp) external;
}

contract GovernanceMockToken {
    mapping(address => uint256) public balanceOf;
    function mint(address to, uint256 amount) external { balanceOf[to] += amount; }
    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(balanceOf[from] >= amount, "balance");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract MigrationGovernanceTest {
    VmMigrationGovernance private constant vm =
        VmMigrationGovernance(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 private constant KEY_A = 0xA11CE;
    uint256 private constant KEY_B = 0xB0B;
    bytes32 private constant MIGRATION = keccak256("governance-migration");
    bytes32 private constant FREEZE = keccak256("governance-freeze");
    bytes32 private constant MANIFEST = keccak256("governance-manifest");

    SourceAuthorizedBindings private bindings;
    VerifiedTokenClaimLedger private ledger;
    BackedTokenSettlement private settlement;
    MigrationGovernance private governance;
    GovernanceMockToken private token;

    function setUp() public {
        address[] memory attesters = new address[](2);
        attesters[0] = vm.addr(KEY_A);
        attesters[1] = vm.addr(KEY_B);
        bindings = new SourceAuthorizedBindings(MIGRATION, 2, attesters);

        address[] memory signers = new address[](2);
        signers[0] = vm.addr(KEY_A);
        signers[1] = vm.addr(KEY_B);
        ledger = new VerifiedTokenClaimLedger(MIGRATION, FREEZE, 1000, 1 days, 2, signers, address(bindings));

        token = new GovernanceMockToken();
        settlement = new BackedTokenSettlement(address(token), address(ledger), address(this), 1000);
        ledger.configureSettlement(address(settlement));
        token.mint(address(this), 1000);
        settlement.fund(1000);

        governance = new MigrationGovernance(address(ledger), 1 days);
        ledger.proposeAdministrator(address(governance));
        governance.acceptLedgerAdministrator();
        governance.grantRole(governance.PROPOSER_ROLE(), address(this));
        governance.grantRole(governance.EXECUTOR_ROLE(), address(this));
        governance.grantRole(governance.GUARDIAN_ROLE(), address(this));
    }

    function _signature(uint256 key, bytes32 digest) internal returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }

    function _signatures(bytes32 digest) internal returns (bytes[] memory out) {
        out = new bytes[](2);
        bytes memory a = _signature(KEY_A, digest);
        bytes memory b = _signature(KEY_B, digest);
        if (vm.addr(KEY_A) < vm.addr(KEY_B)) { out[0] = a; out[1] = b; }
        else { out[0] = b; out[1] = a; }
    }

    function testGuardianCanPauseImmediatelyButUnpauseRequiresTimelock() public {
        governance.pauseImmediately();
        require(ledger.paused(), "guardian pause did not apply");

        bytes memory data = abi.encodeCall(ledger.unpauseClaims, ());
        bytes32 salt = keccak256("unpause-after-review");
        (, uint256 eta) = governance.schedule(salt, data);
        (bool early,) = address(governance).call(abi.encodeCall(governance.execute, (salt, data)));
        require(!early, "timelock bypassed");

        vm.warp(eta);
        governance.execute(salt, data);
        require(!ledger.paused(), "timelocked unpause failed");
    }

    function testEvidenceCanBeCancelledOnlyBeforeActivationThroughTimelock() public {
        bytes32 root = keccak256("candidate-root");
        uint64 activation = uint64(block.timestamp + 5 days);
        bytes[] memory signatures = _signatures(
            ledger.attestationDigest(root, MANIFEST, activation)
        );
        bytes memory proposeData = abi.encodeCall(
            ledger.proposeEvidence, (root, MANIFEST, activation, signatures)
        );
        bytes32 proposeSalt = keccak256("propose-root");
        (, uint256 proposeEta) = governance.schedule(proposeSalt, proposeData);
        vm.warp(proposeEta);
        governance.execute(proposeSalt, proposeData);
        require(ledger.proposed() && ledger.merkleRoot() == root, "proposal missing");

        bytes memory cancelData = abi.encodeCall(ledger.cancelEvidence, ());
        bytes32 cancelSalt = keccak256("cancel-root");
        (, uint256 cancelEta) = governance.schedule(cancelSalt, cancelData);
        vm.warp(cancelEta);
        governance.execute(cancelSalt, cancelData);
        require(!ledger.proposed(), "evidence not cancelled");
        require(ledger.merkleRoot() == bytes32(0), "old root retained");
        require(ledger.manifestHash() == bytes32(0), "old manifest retained");
    }

    function testSurplusRecoveryCannotReduceHolderLiability() public {
        (bool noSurplus,) = address(governance).call(
            abi.encodeCall(governance.execute, (
                keccak256("none"), abi.encodeCall(ledger.recoverSurplus, (address(this), 1))
            ))
        );
        require(!noSurplus, "unfunded recovery unexpectedly executed");

        token.mint(address(settlement), 50);
        bytes memory tooMuch = abi.encodeCall(ledger.recoverSurplus, (address(this), 51));
        bytes32 tooMuchSalt = keccak256("recover-too-much");
        (, uint256 eta) = governance.schedule(tooMuchSalt, tooMuch);
        vm.warp(eta);
        (bool excessive,) = address(governance).call(abi.encodeCall(governance.execute, (tooMuchSalt, tooMuch)));
        require(!excessive, "recovery consumed holder liability");

        bytes memory exact = abi.encodeCall(ledger.recoverSurplus, (address(this), 50));
        bytes32 exactSalt = keccak256("recover-surplus");
        (, eta) = governance.schedule(exactSalt, exact);
        vm.warp(eta);
        governance.execute(exactSalt, exact);
        require(token.balanceOf(address(settlement)) == 1000, "holder backing changed");
        require(settlement.remainingFundedLiability() == 1000, "liability changed");
    }
}
