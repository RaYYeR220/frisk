// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/// @title FriskRegistry
/// @author Frisk
/// @notice An ERC-8004 Validation-Registry-shaped registry for Frisk pre-payment safety
///         verdicts. A validator (Frisk) signs an EIP-712 `Verdict` off-chain; anyone — most
///         often the buyer-agent that received it — can anchor that signed verdict on-chain
///         here. The validator posts a slashable bond, so a wrong "safe" verdict has a cost:
///         a challenger can open a dispute and, if an arbiter rules the validator was wrong,
///         part of the bond is slashed to the challenger. This turns a verdict from an opinion
///         into skin-in-the-game insurance.
/// @dev    Bond integrity: a validator cannot record while unbonding, and withdrawals require a
///         cooldown that exceeds the maximum verdict validity window — so any relied-upon
///         attestation can still be disputed and slashed before its backing bond can leave.
contract FriskRegistry is EIP712, Ownable, ReentrancyGuard {
    using SafeERC20 for IERC20;

    // --------------------------------------------------------------------- //
    //                                Types                                   //
    // --------------------------------------------------------------------- //

    /// @notice The signed verdict. Field order/types match `@frisk/shared` EIP-712 typed data.
    /// @dev decision: 0 = ALLOW, 1 = WARN, 2 = BLOCK.
    struct Verdict {
        bytes32 subject;
        bytes32 intentHash;
        uint8 decision;
        uint16 score;
        bytes32 findingsHash;
        uint64 issuedAt;
        uint64 expiresAt;
        address validator;
        bytes32 nonce;
    }

    /// @notice Stored, anchored attestation.
    struct Attestation {
        bytes32 subject;
        bytes32 intentHash;
        bytes32 findingsHash;
        uint8 decision;
        uint16 score;
        uint64 issuedAt;
        uint64 expiresAt;
        address validator;
        bool slashed;
        bool recorded;
    }

    enum DisputeState {
        None,
        Open,
        Resolved
    }

    struct Dispute {
        address challenger;
        uint256 bond;
        uint256 locked; // exact validator bond locked by THIS dispute
        DisputeState state;
    }

    // --------------------------------------------------------------------- //
    //                               Storage                                  //
    // --------------------------------------------------------------------- //

    bytes32 private constant VERDICT_TYPEHASH = keccak256(
        "Verdict(bytes32 subject,bytes32 intentHash,uint8 decision,uint16 score,bytes32 findingsHash,uint64 issuedAt,uint64 expiresAt,address validator,bytes32 nonce)"
    );

    /// @notice ERC-20 token used for validator bonds and dispute bonds.
    IERC20 public immutable bondToken;

    /// @notice Minimum free+locked bond a validator must hold to record attestations.
    uint256 public minBond;

    /// @notice Bond a challenger must post to open a dispute.
    uint256 public disputeBond;

    /// @notice Amount slashed from a validator's bond when it is ruled wrong.
    uint256 public slashAmount;

    /// @notice Address allowed to resolve disputes.
    address public arbiter;

    /// @notice Cooldown a validator waits after requesting a withdrawal (must exceed
    ///         `maxVerdictWindow` so a relied-upon attestation can still be slashed).
    uint256 public unbondingPeriod;

    /// @notice Maximum `expiresAt - now` a recorded verdict may carry. Bounds how long bond
    ///         must stay slashable and lets the unbonding cooldown fully cover it.
    uint256 public maxVerdictWindow;

    mapping(address => bool) public isValidator;
    /// @notice Total bond a validator has deposited (free + locked).
    mapping(address => uint256) public bondOf;
    /// @notice Portion of a validator's bond currently locked by open disputes.
    mapping(address => uint256) public lockedOf;
    /// @notice Timestamp at which a validator's requested withdrawal unlocks (0 = not unbonding).
    mapping(address => uint256) public unbondableAt;

    mapping(bytes32 => Attestation) private _attestations;
    mapping(bytes32 => Dispute) public disputes;

    // --------------------------------------------------------------------- //
    //                                Events                                  //
    // --------------------------------------------------------------------- //

    event ValidatorRegistered(address indexed validator);
    event BondStaked(address indexed validator, uint256 amount, uint256 total);
    event UnbondRequested(address indexed validator, uint256 unlockAt);
    event BondWithdrawn(address indexed validator, uint256 amount, uint256 total);
    event MinBondUpdated(uint256 minBond);
    event DisputeParamsUpdated(uint256 disputeBond, uint256 slashAmount);
    event ArbiterUpdated(address indexed arbiter);
    event WindowParamsUpdated(uint256 unbondingPeriod, uint256 maxVerdictWindow);

    event AttestationRecorded(
        bytes32 indexed uid, bytes32 indexed subject, uint8 decision, address indexed validator
    );
    event DisputeOpened(bytes32 indexed uid, address indexed challenger, uint256 bond);
    event DisputeResolved(
        bytes32 indexed uid, bool validatorWasWrong, uint256 slashed, address indexed beneficiary
    );

    // --------------------------------------------------------------------- //
    //                                Errors                                  //
    // --------------------------------------------------------------------- //

    error NotValidator();
    error InsufficientBond();
    error BondLocked();
    error AlreadyRecorded();
    error BadSignature();
    error UnknownAttestation();
    error AlreadySlashed();
    error Expired();
    error NotDisputable();
    error DisputeAlreadyOpen();
    error NoOpenDispute();
    error NotArbiter();
    error ZeroAmount();
    error ZeroAddress();
    error Unbonding();
    error WithdrawNotReady();
    error BadVerdictWindow();
    error SelfDispute();
    error BadDecision();

    // --------------------------------------------------------------------- //
    //                             Construction                               //
    // --------------------------------------------------------------------- //

    constructor(IERC20 _bondToken, uint256 _minBond, address _arbiter)
        EIP712("Frisk", "1")
        Ownable(msg.sender)
    {
        bondToken = _bondToken;
        minBond = _minBond;
        disputeBond = _minBond;
        slashAmount = _minBond;
        arbiter = _arbiter == address(0) ? msg.sender : _arbiter;
        maxVerdictWindow = 1 days;
        unbondingPeriod = 7 days; // > maxVerdictWindow, so bond outlives any live attestation
    }

    // --------------------------------------------------------------------- //
    //                          Validator / bonding                           //
    // --------------------------------------------------------------------- //

    /// @notice Register the caller as a validator (idempotent).
    function registerValidator() external {
        _register(msg.sender);
    }

    function _register(address who) internal {
        if (!isValidator[who]) {
            isValidator[who] = true;
            emit ValidatorRegistered(who);
        }
    }

    /// @notice Deposit `amount` of bond token as bond. Auto-registers the caller and re-commits
    ///         any pending unbonding request (you cannot record while unbonding).
    function stake(uint256 amount) external nonReentrant {
        if (amount == 0) revert ZeroAmount();
        _register(msg.sender);
        unbondableAt[msg.sender] = 0; // re-commit: recording requires a committed bond
        bondToken.safeTransferFrom(msg.sender, address(this), amount);
        bondOf[msg.sender] += amount;
        emit BondStaked(msg.sender, amount, bondOf[msg.sender]);
    }

    /// @notice Begin unbonding. Blocks new attestations from this validator and starts the
    ///         withdrawal cooldown. Existing attestations stay slashable until they expire.
    function requestUnbond() external {
        uint256 unlockAt = block.timestamp + unbondingPeriod;
        unbondableAt[msg.sender] = unlockAt;
        emit UnbondRequested(msg.sender, unlockAt);
    }

    /// @notice Withdraw free (unlocked) bond after the unbonding cooldown has elapsed.
    function withdraw(uint256 amount) external nonReentrant {
        if (amount == 0) revert ZeroAmount();
        uint256 unlockAt = unbondableAt[msg.sender];
        if (unlockAt == 0) revert Unbonding(); // must requestUnbond() first
        if (block.timestamp < unlockAt) revert WithdrawNotReady();
        uint256 free = bondOf[msg.sender] - lockedOf[msg.sender];
        if (amount > free) revert BondLocked();
        bondOf[msg.sender] -= amount;
        bondToken.safeTransfer(msg.sender, amount);
        emit BondWithdrawn(msg.sender, amount, bondOf[msg.sender]);
    }

    /// @notice Free (withdrawable-after-cooldown) bond of a validator.
    function freeBondOf(address validator) external view returns (uint256) {
        return bondOf[validator] - lockedOf[validator];
    }

    // --------------------------------------------------------------------- //
    //                             Attestations                               //
    // --------------------------------------------------------------------- //

    /// @notice Deterministic EIP-712 digest of a verdict; also its storage key (uid).
    function uidOf(Verdict calldata v) public view returns (bytes32) {
        return _hashTypedDataV4(_structHash(v));
    }

    function _structHash(Verdict calldata v) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                VERDICT_TYPEHASH,
                v.subject,
                v.intentHash,
                v.decision,
                v.score,
                v.findingsHash,
                v.issuedAt,
                v.expiresAt,
                v.validator,
                v.nonce
            )
        );
    }

    /// @notice Anchor a validator-signed verdict on-chain. Callable by anyone.
    /// @param v The verdict struct that was signed.
    /// @param sig The validator's EIP-712 signature over `v`.
    /// @return uid The attestation id (EIP-712 digest).
    function recordAttestation(Verdict calldata v, bytes calldata sig)
        external
        returns (bytes32 uid)
    {
        if (v.decision > 2) revert BadDecision();
        // Bound the validity window so the unbonding cooldown fully covers it.
        if (v.expiresAt <= block.timestamp || v.expiresAt > block.timestamp + maxVerdictWindow) {
            revert BadVerdictWindow();
        }

        uid = _hashTypedDataV4(_structHash(v));
        if (_attestations[uid].recorded) revert AlreadyRecorded();

        address signer = ECDSA.recover(uid, sig);
        if (signer != v.validator) revert BadSignature();
        if (!isValidator[v.validator]) revert NotValidator();
        if (bondOf[v.validator] < minBond) revert InsufficientBond();
        // A validator that has begun unbonding cannot back new attestations.
        if (unbondableAt[v.validator] != 0) revert Unbonding();

        _attestations[uid] = Attestation({
            subject: v.subject,
            intentHash: v.intentHash,
            findingsHash: v.findingsHash,
            decision: v.decision,
            score: v.score,
            issuedAt: v.issuedAt,
            expiresAt: v.expiresAt,
            validator: v.validator,
            slashed: false,
            recorded: true
        });

        emit AttestationRecorded(uid, v.subject, v.decision, v.validator);
    }

    /// @notice Fetch a stored attestation.
    function getAttestation(bytes32 uid) external view returns (Attestation memory) {
        Attestation memory a = _attestations[uid];
        if (!a.recorded) revert UnknownAttestation();
        return a;
    }

    /// @notice True if the attestation exists, is not slashed and has not expired.
    function isValid(bytes32 uid) external view returns (bool) {
        Attestation memory a = _attestations[uid];
        return a.recorded && !a.slashed && block.timestamp <= a.expiresAt;
    }

    // --------------------------------------------------------------------- //
    //                          Disputes / slashing                           //
    // --------------------------------------------------------------------- //

    /// @notice Challenge a "safe" (ALLOW/WARN) attestation before it expires by posting a bond.
    ///         A BLOCK verdict cannot be disputed — Frisk warned; there is nothing to insure.
    ///         The validator cannot dispute its own attestation.
    function openDispute(bytes32 uid) external nonReentrant {
        Attestation storage a = _attestations[uid];
        if (!a.recorded) revert UnknownAttestation();
        if (a.slashed) revert AlreadySlashed();
        if (a.decision == 2) revert NotDisputable(); // BLOCK is not insurable
        if (block.timestamp > a.expiresAt) revert Expired();
        if (msg.sender == a.validator) revert SelfDispute();

        Dispute storage d = disputes[uid];
        if (d.state == DisputeState.Open) revert DisputeAlreadyOpen();

        // Lock the slashable portion of the validator's bond so it cannot be withdrawn while the
        // dispute is pending. Cap at the validator's available bond; remember the exact amount.
        uint256 lock = slashAmount;
        uint256 available = bondOf[a.validator] - lockedOf[a.validator];
        if (lock > available) lock = available;
        lockedOf[a.validator] += lock;

        d.challenger = msg.sender;
        d.bond = disputeBond;
        d.locked = lock;
        d.state = DisputeState.Open;

        bondToken.safeTransferFrom(msg.sender, address(this), disputeBond);

        emit DisputeOpened(uid, msg.sender, disputeBond);
    }

    /// @notice Arbiter resolves an open dispute.
    /// @param validatorWasWrong If true, slash the validator's locked bond to the challenger
    ///        (plus the challenger's bond back) and permanently invalidate the attestation. If
    ///        false, the challenger's bond goes to the validator and the dispute is cleared so an
    ///        honest challenger may still dispute later (a sham cannot immunize the attestation).
    function resolveDispute(bytes32 uid, bool validatorWasWrong) external nonReentrant {
        if (msg.sender != arbiter) revert NotArbiter();

        Dispute storage d = disputes[uid];
        if (d.state != DisputeState.Open) revert NoOpenDispute();

        Attestation storage a = _attestations[uid];
        address validator = a.validator;
        address challenger = d.challenger;
        uint256 challengerBond = d.bond;
        uint256 lockedForThis = d.locked;

        // Release the exact lock this dispute took.
        lockedOf[validator] -= lockedForThis;

        uint256 slashed = 0;
        address beneficiary;

        if (validatorWasWrong) {
            a.slashed = true;
            slashed = lockedForThis;
            bondOf[validator] -= slashed;
            beneficiary = challenger;
            d.state = DisputeState.Resolved;
            uint256 payout = challengerBond + slashed;
            if (payout > 0) bondToken.safeTransfer(challenger, payout);
        } else {
            // Frivolous: challenger's bond credited to the validator; clear the dispute so a
            // genuine challenger is not permanently locked out by a sham challenge.
            beneficiary = validator;
            bondOf[validator] += challengerBond;
            delete disputes[uid];
        }

        emit DisputeResolved(uid, validatorWasWrong, slashed, beneficiary);
    }

    // --------------------------------------------------------------------- //
    //                                 Admin                                  //
    // --------------------------------------------------------------------- //

    function setMinBond(uint256 _minBond) external onlyOwner {
        minBond = _minBond;
        emit MinBondUpdated(_minBond);
    }

    function setDisputeParams(uint256 _disputeBond, uint256 _slashAmount) external onlyOwner {
        disputeBond = _disputeBond;
        slashAmount = _slashAmount;
        emit DisputeParamsUpdated(_disputeBond, _slashAmount);
    }

    function setArbiter(address _arbiter) external onlyOwner {
        if (_arbiter == address(0)) revert ZeroAddress();
        arbiter = _arbiter;
        emit ArbiterUpdated(_arbiter);
    }

    /// @notice Update the unbonding cooldown and max verdict window. The cooldown must stay
    ///         at least as long as the window so bond can never leave before an attestation
    ///         it backs has expired.
    function setWindowParams(uint256 _unbondingPeriod, uint256 _maxVerdictWindow) external onlyOwner {
        if (_unbondingPeriod < _maxVerdictWindow) revert BadVerdictWindow();
        unbondingPeriod = _unbondingPeriod;
        maxVerdictWindow = _maxVerdictWindow;
        emit WindowParamsUpdated(_unbondingPeriod, _maxVerdictWindow);
    }

    /// @notice EIP-712 domain separator (for off-chain signers to cross-check).
    function domainSeparator() external view returns (bytes32) {
        return _domainSeparatorV4();
    }
}
