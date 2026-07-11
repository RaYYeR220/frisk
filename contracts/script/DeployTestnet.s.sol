// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console2} from "forge-std/Script.sol";
import {FriskRegistry} from "../src/FriskRegistry.sol";
import {MockERC20} from "../test/mocks/MockERC20.sol";

/// @notice Full testnet bring-up: deploy a bond token, deploy FriskRegistry, register + stake.
///   PK=<operator key> forge script script/DeployTestnet.s.sol:DeployTestnet \
///     --rpc-url https://testrpc.xlayer.tech/terigon --broadcast
contract DeployTestnet is Script {
    function run() external {
        uint256 pk = vm.envUint("PK");
        address deployer = vm.addr(pk);
        uint256 minBond = 100e6; // 100 units @ 6dp

        vm.startBroadcast(pk);
        MockERC20 bond = new MockERC20("Frisk Bond USD", "fbUSD", 6);
        bond.mint(deployer, 1_000_000e6);
        FriskRegistry reg = new FriskRegistry(bond, minBond, deployer);
        bond.approve(address(reg), type(uint256).max);
        reg.stake(1_000e6); // stake 1000 so we're comfortably above minBond
        vm.stopBroadcast();

        console2.log("MockBond:", address(bond));
        console2.log("FriskRegistry:", address(reg));
        console2.log("deployer/validator:", deployer);
        console2.log("bondOf(deployer):", reg.bondOf(deployer));
    }
}
