// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console2} from "forge-std/Test.sol";
import {FriskRegistry} from "../src/FriskRegistry.sol";
import {MockERC20} from "./mocks/MockERC20.sol";

contract FriskRegistryTest is Test {
    FriskRegistry internal reg;
    MockERC20 internal bond;

    uint256 internal validatorPk = 0xA11CE;
    address internal validator;
    address internal challenger = address(0xCA11);
    address internal challenger2 = address(0xCA12);
    address internal arbiter = address(0xA187);

    uint256 internal constant MIN_BOND = 100e6; // 100 USDT0 (6 dec)

    function setUp() public {
        validator = vm.addr(validatorPk);
        bond = new MockERC20("USDT0", "USDT0", 6);
        reg = new FriskRegistry(bond, MIN_BOND, arbiter);

        bond.mint(validator, 1_000e6);
        bond.mint(challenger, 1_000e6);
        bond.mint(challenger2, 1_000e6);

        vm.prank(validator);
        bond.approve(address(reg), type(uint256).max);
        vm.prank(challenger);
        bond.approve(address(reg), type(uint256).max);
        vm.prank(challenger2);
        bond.approve(address(reg), type(uint256).max);
    }

    // --------------------------- helpers --------------------------- //

    function _verdict(uint8 decision) internal view returns (FriskRegistry.Verdict memory v) {
        v = FriskRegistry.Verdict({
            subject: keccak256("subject:seller-agent-42"),
            intentHash: keccak256("intent:pay-0.5-usdt0"),
            decision: decision,
            score: decision == 2 ? uint16(95) : uint16(10),
            findingsHash: keccak256("findings"),
            issuedAt: uint64(block.timestamp),
            expiresAt: uint64(block.timestamp + 600),
            validator: validator,
            nonce: keccak256("nonce:1")
        });
    }

    function _sign(FriskRegistry.Verdict memory v, uint256 pk) internal view returns (bytes memory) {
        bytes32 digest = reg.uidOf(v);
        (uint8 vv, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, vv);
    }

    function _stakeMin() internal {
        vm.prank(validator);
        reg.stake(MIN_BOND);
    }

    function _stake(uint256 amount) internal {
        vm.prank(validator);
        reg.stake(amount);
    }

    // --------------------------- record --------------------------- //

    function test_record_valid() public {
        _stakeMin();
        FriskRegistry.Verdict memory v = _verdict(0);
        bytes32 uid = reg.recordAttestation(v, _sign(v, validatorPk));
        assertEq(uid, reg.uidOf(v));
        assertTrue(reg.isValid(uid));
        FriskRegistry.Attestation memory a = reg.getAttestation(uid);
        assertEq(a.validator, validator);
        assertEq(a.decision, 0);
        assertTrue(a.recorded);
    }

    function test_record_revert_wrongSigner() public {
        _stakeMin();
        FriskRegistry.Verdict memory v = _verdict(0);
        bytes memory sig = _sign(v, 0xB0B);
        vm.expectRevert(FriskRegistry.BadSignature.selector);
        reg.recordAttestation(v, sig);
    }

    function test_record_revert_tamperedField() public {
        _stakeMin();
        FriskRegistry.Verdict memory v = _verdict(0);
        bytes memory sig = _sign(v, validatorPk);
        v.score = 1;
        vm.expectRevert(FriskRegistry.BadSignature.selector);
        reg.recordAttestation(v, sig);
    }

    function test_record_revert_insufficientBond() public {
        vm.prank(validator);
        reg.stake(MIN_BOND - 1);
        FriskRegistry.Verdict memory v = _verdict(0);
        bytes memory sig = _sign(v, validatorPk);
        vm.expectRevert(FriskRegistry.InsufficientBond.selector);
        reg.recordAttestation(v, sig);
    }

    function test_record_revert_replay() public {
        _stakeMin();
        FriskRegistry.Verdict memory v = _verdict(0);
        bytes memory sig = _sign(v, validatorPk);
        reg.recordAttestation(v, sig);
        vm.expectRevert(FriskRegistry.AlreadyRecorded.selector);
        reg.recordAttestation(v, sig);
    }

    function test_record_revert_badDecision() public {
        _stakeMin();
        FriskRegistry.Verdict memory v = _verdict(0);
        v.decision = 3;
        bytes memory sig = _sign(v, validatorPk);
        vm.expectRevert(FriskRegistry.BadDecision.selector);
        reg.recordAttestation(v, sig);
    }

    function test_record_revert_windowTooLong() public {
        _stakeMin();
        FriskRegistry.Verdict memory v = _verdict(0);
        v.expiresAt = uint64(block.timestamp + 2 days); // > maxVerdictWindow (1 day)
        bytes memory sig = _sign(v, validatorPk);
        vm.expectRevert(FriskRegistry.BadVerdictWindow.selector);
        reg.recordAttestation(v, sig);
    }

    function test_record_revert_alreadyExpired() public {
        _stakeMin();
        vm.warp(block.timestamp + 1000);
        FriskRegistry.Verdict memory v = _verdict(0);
        v.expiresAt = uint64(block.timestamp - 1);
        bytes memory sig = _sign(v, validatorPk);
        vm.expectRevert(FriskRegistry.BadVerdictWindow.selector);
        reg.recordAttestation(v, sig);
    }

    function test_record_revert_whileUnbonding() public {
        _stakeMin();
        FriskRegistry.Verdict memory v = _verdict(0);
        bytes memory sig = _sign(v, validatorPk);
        vm.prank(validator);
        reg.requestUnbond();
        vm.expectRevert(FriskRegistry.Unbonding.selector);
        reg.recordAttestation(v, sig);
    }

    function test_isValid_expiry() public {
        _stakeMin();
        FriskRegistry.Verdict memory v = _verdict(0);
        bytes32 uid = reg.recordAttestation(v, _sign(v, validatorPk));
        assertTrue(reg.isValid(uid));
        vm.warp(block.timestamp + 601);
        assertFalse(reg.isValid(uid));
    }

    // --------------------------- bonding --------------------------- //

    function test_withdraw_afterCooldown_ok() public {
        _stake(200e6);
        vm.prank(validator);
        reg.requestUnbond();
        vm.warp(block.timestamp + 7 days);
        vm.prank(validator);
        reg.withdraw(50e6);
        assertEq(reg.bondOf(validator), 150e6);
    }

    function test_withdraw_revert_withoutRequest() public {
        _stake(200e6);
        vm.prank(validator);
        vm.expectRevert(FriskRegistry.Unbonding.selector);
        reg.withdraw(1);
    }

    function test_withdraw_revert_beforeCooldown() public {
        _stake(200e6);
        vm.prank(validator);
        reg.requestUnbond();
        vm.warp(block.timestamp + 1 days); // < 7 day cooldown
        vm.prank(validator);
        vm.expectRevert(FriskRegistry.WithdrawNotReady.selector);
        reg.withdraw(1);
    }

    /// HIGH-1 regression: a validator cannot record then instantly escape its bond.
    function test_cannot_record_then_immediately_withdraw() public {
        _stakeMin();
        FriskRegistry.Verdict memory v = _verdict(0);
        reg.recordAttestation(v, _sign(v, validatorPk));
        // requesting unbond now blocks further records, and withdrawal waits out the cooldown,
        // which exceeds the verdict window — so the attestation can still be slashed meanwhile.
        vm.prank(validator);
        reg.requestUnbond();
        vm.prank(validator);
        vm.expectRevert(FriskRegistry.WithdrawNotReady.selector);
        reg.withdraw(MIN_BOND);
    }

    function test_withdraw_locked_reverts() public {
        _stakeMin();
        FriskRegistry.Verdict memory v = _verdict(0);
        bytes32 uid = reg.recordAttestation(v, _sign(v, validatorPk));
        vm.prank(challenger);
        reg.openDispute(uid);
        vm.prank(validator);
        reg.requestUnbond();
        vm.warp(block.timestamp + 7 days);
        vm.prank(validator);
        vm.expectRevert(FriskRegistry.BondLocked.selector);
        reg.withdraw(1);
    }

    // --------------------------- disputes --------------------------- //

    function test_dispute_slash_happy() public {
        _stakeMin();
        FriskRegistry.Verdict memory v = _verdict(1); // WARN — insurable
        bytes32 uid = reg.recordAttestation(v, _sign(v, validatorPk));

        uint256 chalBefore = bond.balanceOf(challenger);
        vm.prank(challenger);
        reg.openDispute(uid);
        assertEq(bond.balanceOf(challenger), chalBefore - MIN_BOND);

        vm.prank(arbiter);
        reg.resolveDispute(uid, true);

        assertEq(bond.balanceOf(challenger), chalBefore + MIN_BOND); // dispute bond back + slash
        assertEq(reg.bondOf(validator), 0);
        assertFalse(reg.isValid(uid));
        assertTrue(reg.getAttestation(uid).slashed);
    }

    /// HIGH-2 regression: the validator cannot dispute its own attestation.
    function test_openDispute_revert_selfDispute() public {
        _stakeMin();
        FriskRegistry.Verdict memory v = _verdict(0);
        bytes32 uid = reg.recordAttestation(v, _sign(v, validatorPk));
        vm.prank(validator);
        vm.expectRevert(FriskRegistry.SelfDispute.selector);
        reg.openDispute(uid);
    }

    /// HIGH-2 regression: a frivolous resolution does NOT permanently immunize the attestation.
    function test_reDispute_after_frivolous() public {
        _stakeMin();
        FriskRegistry.Verdict memory v = _verdict(0);
        bytes32 uid = reg.recordAttestation(v, _sign(v, validatorPk));

        // First (sham) dispute → arbiter rules frivolous.
        vm.prank(challenger);
        reg.openDispute(uid);
        vm.prank(arbiter);
        reg.resolveDispute(uid, false);
        assertEq(reg.lockedOf(validator), 0);

        // A genuine challenger can still dispute — not locked out.
        vm.prank(challenger2);
        reg.openDispute(uid);
        vm.prank(arbiter);
        reg.resolveDispute(uid, true);
        assertTrue(reg.getAttestation(uid).slashed);
    }

    function test_dispute_frivolous_creditsValidator() public {
        _stakeMin();
        FriskRegistry.Verdict memory v = _verdict(0);
        bytes32 uid = reg.recordAttestation(v, _sign(v, validatorPk));
        vm.prank(challenger);
        reg.openDispute(uid);
        vm.prank(arbiter);
        reg.resolveDispute(uid, false);
        assertEq(reg.bondOf(validator), MIN_BOND + MIN_BOND);
        assertEq(reg.lockedOf(validator), 0);
        assertTrue(reg.isValid(uid));
    }

    function test_dispute_revert_onBlock() public {
        _stakeMin();
        FriskRegistry.Verdict memory v = _verdict(2);
        bytes32 uid = reg.recordAttestation(v, _sign(v, validatorPk));
        vm.prank(challenger);
        vm.expectRevert(FriskRegistry.NotDisputable.selector);
        reg.openDispute(uid);
    }

    function test_dispute_revert_doubleOpen() public {
        _stakeMin();
        FriskRegistry.Verdict memory v = _verdict(0);
        bytes32 uid = reg.recordAttestation(v, _sign(v, validatorPk));
        vm.prank(challenger);
        reg.openDispute(uid);
        vm.prank(challenger2);
        vm.expectRevert(FriskRegistry.DisputeAlreadyOpen.selector);
        reg.openDispute(uid);
    }

    function test_resolve_revert_notArbiter() public {
        _stakeMin();
        FriskRegistry.Verdict memory v = _verdict(0);
        bytes32 uid = reg.recordAttestation(v, _sign(v, validatorPk));
        vm.prank(challenger);
        reg.openDispute(uid);
        vm.expectRevert(FriskRegistry.NotArbiter.selector);
        reg.resolveDispute(uid, true);
    }

    function test_resolve_revert_twice() public {
        _stakeMin();
        FriskRegistry.Verdict memory v = _verdict(0);
        bytes32 uid = reg.recordAttestation(v, _sign(v, validatorPk));
        vm.prank(challenger);
        reg.openDispute(uid);
        vm.prank(arbiter);
        reg.resolveDispute(uid, true);
        vm.prank(arbiter);
        vm.expectRevert(FriskRegistry.NoOpenDispute.selector);
        reg.resolveDispute(uid, true);
    }

    /// MEDIUM-1 regression: the lock is stored per-dispute, so changing slashAmount mid-dispute
    /// does not freeze bond or mis-slash — resolve releases exactly what was locked.
    function test_perDispute_lock_survives_param_change() public {
        _stake(300e6);
        FriskRegistry.Verdict memory v = _verdict(0);
        bytes32 uid = reg.recordAttestation(v, _sign(v, validatorPk));

        vm.prank(challenger);
        reg.openDispute(uid); // locks slashAmount (== MIN_BOND == 100e6)
        assertEq(reg.lockedOf(validator), MIN_BOND);

        // Owner shrinks slashAmount while the dispute is open.
        reg.setDisputeParams(MIN_BOND, 30e6);

        vm.prank(arbiter);
        reg.resolveDispute(uid, true);

        // Exactly the originally-locked 100e6 is slashed and released — no frozen remainder.
        assertEq(reg.lockedOf(validator), 0);
        assertEq(reg.bondOf(validator), 200e6);
    }

    // --------------------------- admin --------------------------- //

    function test_setArbiter_revert_zero() public {
        vm.expectRevert(FriskRegistry.ZeroAddress.selector);
        reg.setArbiter(address(0));
    }

    // ------------------- EIP-712 parity with TS ------------------- //

    /// @notice Logs the uid + domain for a FIXED verdict at chainId 196 so we can assert the
    ///         off-chain shared attestationUID() computes the identical value.
    function test_log_uid_parity() public {
        vm.chainId(196);
        FriskRegistry reg196 = new FriskRegistry(bond, MIN_BOND, arbiter);
        FriskRegistry.Verdict memory v = FriskRegistry.Verdict({
            subject: bytes32(uint256(0xBEEF)),
            intentHash: bytes32(uint256(0x1111)),
            decision: 2,
            score: 95,
            findingsHash: bytes32(uint256(0x2222)),
            issuedAt: 1000,
            expiresAt: 2000,
            validator: 0x3333333333333333333333333333333333333333,
            nonce: bytes32(uint256(0x4444))
        });
        console2.log("PARITY verifyingContract:", address(reg196));
        console2.logBytes32(reg196.uidOf(v));
    }
}
