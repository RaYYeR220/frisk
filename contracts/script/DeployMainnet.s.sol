// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console2} from "forge-std/Script.sol";
import {FriskRegistry} from "../src/FriskRegistry.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @notice Mainnet bring-up: deploy FriskRegistry against a real bond token (USDT0), then
///         approve + stake so the validator can immediately anchor attestations.
///
/// Env:
///   PK          operator/validator key (deployer, signer)
///   BOND_TOKEN  ERC20 bond token — X Layer mainnet USDT0 = 0x779Ded0c9e1022225f8E0630b35a9b54bE713736
///   MIN_BOND    minimum validator bond in base units (0.1 USDT0 @ 6dp = 100000)
///   STAKE_AMT   amount to stake in base units (>= MIN_BOND)
///   ARBITER     optional dispute arbiter (defaults to the deployer)
///
///   PK=$FRISK_KEY_PK BOND_TOKEN=0x779Ded0c9e1022225f8E0630b35a9b54bE713736 MIN_BOND=100000 STAKE_AMT=100000 \
///     forge script script/DeployMainnet.s.sol:DeployMainnet --rpc-url https://rpc.xlayer.tech --broadcast
contract DeployMainnet is Script {
    function run() external {
        uint256 pk = vm.envUint("PK");
        address deployer = vm.addr(pk);
        IERC20 bond = IERC20(vm.envAddress("BOND_TOKEN"));
        uint256 minBond = vm.envUint("MIN_BOND");
        uint256 stakeAmt = vm.envUint("STAKE_AMT");
        address arbiter = vm.envOr("ARBITER", deployer);

        vm.startBroadcast(pk);
        FriskRegistry reg = new FriskRegistry(bond, minBond, arbiter);
        bond.approve(address(reg), stakeAmt);
        reg.stake(stakeAmt);
        vm.stopBroadcast();

        console2.log("FriskRegistry:", address(reg));
        console2.log("bondToken:", address(bond));
        console2.log("minBond:", minBond);
        console2.log("bondOf(deployer):", reg.bondOf(deployer));
        console2.log("domainSeparator:");
        console2.logBytes32(reg.domainSeparator());
    }
}
