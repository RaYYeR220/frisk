// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console2} from "forge-std/Script.sol";
import {FriskRegistry} from "../src/FriskRegistry.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @notice Deploys FriskRegistry.
///
/// Env:
///   BOND_TOKEN  ERC20 used for validator/dispute bonds (X Layer mainnet USDT0 =
///               0x779Ded0c9e1022225f8E0630b35a9b54bE713736).
///   MIN_BOND    minimum validator bond in token base units (e.g. 100000000 = 100 USDT0 @ 6dp).
///   ARBITER     dispute arbiter address (defaults to the deployer if unset/zero).
///
/// X Layer TESTNET (chainId 1952) — deploy first:
///   forge script script/Deploy.s.sol:Deploy \
///     --rpc-url https://testrpc.xlayer.tech/terigon --broadcast --private-key $PK
///
/// X Layer MAINNET (chainId 196) — after testnet passes:
///   forge script script/Deploy.s.sol:Deploy \
///     --rpc-url https://rpc.xlayer.tech --broadcast --private-key $PK
///
/// Verify on OKLink (X Layer):
///   forge verify-contract <ADDR> src/FriskRegistry.sol:FriskRegistry \
///     --verifier oklink --chain 196 --watch \
///     --constructor-args $(cast abi-encode "constructor(address,uint256,address)" $BOND_TOKEN $MIN_BOND $ARBITER)
contract Deploy is Script {
    function run() external returns (FriskRegistry registry) {
        address bondToken = vm.envAddress("BOND_TOKEN");
        uint256 minBond = vm.envUint("MIN_BOND");
        address arbiter = vm.envOr("ARBITER", address(0));

        vm.startBroadcast();
        registry = new FriskRegistry(IERC20(bondToken), minBond, arbiter);
        vm.stopBroadcast();

        console2.log("FriskRegistry deployed:", address(registry));
        console2.log("bondToken:", bondToken);
        console2.log("minBond:", minBond);
        console2.log("domainSeparator:");
        console2.logBytes32(registry.domainSeparator());
    }
}
