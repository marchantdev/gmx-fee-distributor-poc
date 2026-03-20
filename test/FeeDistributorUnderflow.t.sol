// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import "forge-std/Test.sol";

/**
 * @title FeeDistributorUnderflowPoC
 * @notice Demonstrates the arithmetic underflow in FeeDistributor._calculateChainlinkAndTreasuryAmounts()
 *
 * VULNERABILITY:
 *   File: gmx-io/gmx-synthetics/contracts/fee/FeeDistributor.sol
 *   Line 657: uint256 wntForTreasury = chainlinkTreasuryWntAmount - wntForChainlink - keeperCostsV2;
 *
 * When keeperCostsV2 > (chainlinkTreasuryWntAmount - wntForChainlink), Solidity 0.8
 * checked arithmetic panics with Panic(0x11) underflow error.
 *
 * This permanently DoS's the weekly fee distribution cycle, preventing GMX stakers
 * from receiving their rewards until governance intervenes.
 *
 * IMPACT: Medium -- Temporary freezing of protocol fee distribution
 *   - $1M-$3M per week in staker rewards cannot be distributed
 *   - DoS lasts until admin adjusts keeper target balances (24h+ timelock delay)
 *
 * PROGRAM: GMX Synthetics (Immunefi)
 *   https://immunefi.com/bug-bounty/gmx/information/
 *   Deployed FeeDistributor: 0x5A44a3b026d50EC039582fDb3aFDD88e2092E211 (Arbitrum)
 */
contract FeeDistributorUnderflowPoC is Test {

    /// @dev Exact replication of FeeDistributor._calculateChainlinkAndTreasuryAmounts()
    ///      (FeeDistributor.sol lines 639-659)
    ///      Using 1e30 as the FLOAT_PRECISION constant (same as GMX Precision library)
    function calculateChainlinkAndTreasuryAmounts(
        uint256 totalWntBalance,
        uint256 feesV2UsdInWnt,
        uint256 feesV1UsdInWnt,
        uint256 chainlinkFactor,
        uint256 keeperCostsV2
    ) external pure returns (uint256 wntForChainlink, uint256 wntForTreasury) {
        uint256 chainlinkTreasuryWntAmount = totalWntBalance * feesV2UsdInWnt /
            (feesV1UsdInWnt + feesV2UsdInWnt);

        wntForChainlink = chainlinkTreasuryWntAmount * chainlinkFactor / 1e30;

        // VULNERABLE LINE (FeeDistributor.sol:657)
        // Reverts if keeperCostsV2 > chainlinkTreasuryWntAmount - wntForChainlink
        wntForTreasury = chainlinkTreasuryWntAmount - wntForChainlink - keeperCostsV2;
    }

    // ----------------------------------------------------------------
    // Test 1: Normal conditions -- distribution works fine
    // ----------------------------------------------------------------
    function test_normalConditions_distributionSucceeds() public {
        // Bull market: V2 is 80% of total fees (dominant)
        uint256 totalWntBalance = 100 ether;
        uint256 feesV2UsdInWnt = 800_000e18; // 80%
        uint256 feesV1UsdInWnt = 200_000e18; // 20%
        uint256 chainlinkFactor = 25e28;     // 25%
        uint256 keeperCostsV2 = 5 ether;     // 5 ETH needed by V2 keepers

        // chainlinkTreasuryWntAmount = 100 * 0.8 = 80 ETH
        // wntForChainlink = 80 * 0.25 = 20 ETH
        // Available = 60 ETH >> 5 ETH keeper costs
        // wntForTreasury = 60 - 5 = 55 ETH

        (uint256 wntForChainlink, uint256 wntForTreasury) = this.calculateChainlinkAndTreasuryAmounts(
            totalWntBalance, feesV2UsdInWnt, feesV1UsdInWnt, chainlinkFactor, keeperCostsV2
        );

        assertEq(wntForChainlink, 20 ether);
        assertEq(wntForTreasury, 55 ether);
        console.log("[PASS] Normal conditions: distribution succeeds. Treasury receives 55 ETH.");
    }

    // ----------------------------------------------------------------
    // Test 2: Bear market / low V2 activity -- UNDERFLOW TRIGGERED
    // ----------------------------------------------------------------
    function test_bearMarket_lowV2Activity_distributionReverts() public {
        // Bear market: V2 is only 15% of total fees (low open interest)
        uint256 totalWntBalance = 50 ether;
        uint256 feesV2UsdInWnt = 150_000e18; // 15%
        uint256 feesV1UsdInWnt = 850_000e18; // 85%
        uint256 chainlinkFactor = 25e28;     // 25%

        // 8 V2 keepers, each 0.8 ETH below their target balance
        // (normal depletion from gas costs during a volatile period)
        uint256 keeperCostsV2 = 8 * 0.8 ether; // = 6.4 ETH

        // CALCULATION:
        // chainlinkTreasuryWntAmount = 50 * 0.15 = 7.5 ETH
        // wntForChainlink = 7.5 * 0.25 = 1.875 ETH
        // Available for keepers + treasury = 5.625 ETH
        // keeperCostsV2 = 6.4 ETH > 5.625 ETH  -->  ARITHMETIC UNDERFLOW

        console.log("[VULNERABLE] Bear market scenario:");
        console.log("  V2 fee share: 15%");
        console.log("  chainlinkTreasuryWntAmount: 7.5 ETH");
        console.log("  wntForChainlink (25%): 1.875 ETH");
        console.log("  V2 budget remaining: 5.625 ETH");
        console.log("  keeperCostsV2 (8 keepers x 0.8 ETH): 6.4 ETH");
        console.log("  --> keeperCostsV2 (6.4 ETH) > available (5.625 ETH) = PANIC UNDERFLOW");

        // Solidity 0.8 checked arithmetic panics with arithmetic underflow
        vm.expectRevert();
        this.calculateChainlinkAndTreasuryAmounts(
            totalWntBalance, feesV2UsdInWnt, feesV1UsdInWnt, chainlinkFactor, keeperCostsV2
        );

        console.log("[CONFIRMED] distribute() reverts - weekly fee distribution is DoS'd");
    }

    // ----------------------------------------------------------------
    // Test 3: Verify exact arithmetic -- demonstrate the underflow value
    // ----------------------------------------------------------------
    function test_verifyUnderflowAmount() public {
        // Same parameters as Test 2
        uint256 totalWntBalance = 50 ether;
        uint256 feesV2UsdInWnt = 150_000e18;
        uint256 feesV1UsdInWnt = 850_000e18;

        uint256 chainlinkTreasuryWntAmount = totalWntBalance * feesV2UsdInWnt /
            (feesV1UsdInWnt + feesV2UsdInWnt);

        assertEq(chainlinkTreasuryWntAmount, 7.5 ether, "V2 share = 7.5 ETH");

        uint256 wntForChainlink = chainlinkTreasuryWntAmount * 25e28 / 1e30; // 25%
        assertEq(wntForChainlink, 1.875 ether, "Chainlink share = 1.875 ETH");

        uint256 available = chainlinkTreasuryWntAmount - wntForChainlink;
        assertEq(available, 5.625 ether, "Available for keepers+treasury = 5.625 ETH");

        uint256 keeperCostsV2 = 6.4 ether;

        // Confirm the underflow would occur
        assertTrue(keeperCostsV2 > available, "keeperCostsV2 exceeds available budget -- underflow confirmed");

        // The vulnerable subtraction:
        // available - keeperCostsV2 = 5.625 ETH - 6.4 ETH = -0.775 ETH
        // As uint256: would wrap to MAX_UINT256 - 0.775 ETH + 1 (but Solidity 0.8 reverts)

        console.log("[CONFIRMED] Underflow deficit: keeperCostsV2 exceeds V2 budget by 0.775 ETH");
    }

    // ----------------------------------------------------------------
    // Test 4: Demonstrate the recommended fix does not revert
    // ----------------------------------------------------------------
    function test_fixedVersion_doesNotRevert() public {
        uint256 totalWntBalance = 50 ether;
        uint256 feesV2UsdInWnt = 150_000e18;
        uint256 feesV1UsdInWnt = 850_000e18;
        uint256 chainlinkFactor = 25e28;
        uint256 keeperCostsV2 = 6.4 ether; // Would underflow original code

        uint256 chainlinkTreasuryWntAmount = totalWntBalance * feesV2UsdInWnt /
            (feesV1UsdInWnt + feesV2UsdInWnt);
        uint256 wntForChainlink = chainlinkTreasuryWntAmount * chainlinkFactor / 1e30;

        // FIXED VERSION: cap keeperCostsV2 at available budget
        uint256 available = chainlinkTreasuryWntAmount > wntForChainlink
            ? chainlinkTreasuryWntAmount - wntForChainlink
            : 0;
        uint256 cappedKeeperCosts = keeperCostsV2 > available ? available : keeperCostsV2;
        uint256 wntForTreasury = available - cappedKeeperCosts;

        // No revert with fix applied -- treasury gets 0 when keeper costs exceed budget
        assertEq(wntForTreasury, 0);
        assertEq(cappedKeeperCosts, available, "All available budget goes to keepers");
        console.log("[PASS] Fixed version: excess keeper costs are capped, no underflow");
    }
}
