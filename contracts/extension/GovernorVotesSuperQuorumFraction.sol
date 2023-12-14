// SPDX-License-Identifier: MIT
// Original design by OpenZeppelin
// Modified by Dennison Bertram @ Tally.xyz
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/governance/extensions/GovernorVotes.sol";
import "@openzeppelin/contracts/utils/math/SafeCast.sol";
import "@openzeppelin/contracts/utils/structs/Checkpoints.sol";

/// @title GovernorVotesSuperQuorumFraction
/// @notice Extends GovernorVotes to add super quorum functionality based on a fraction of the total token supply.
/// @dev This contract adds an additional quorum mechanism to the standard GovernorVotes functionality.
abstract contract GovernorVotesSuperQuorumFraction is GovernorVotes {
    using Checkpoints for Checkpoints.Trace208;

    Checkpoints.Trace208 private _superQuorumNumeratorHistory;

    event SuperQuorumNumeratorUpdated(uint256 oldQuorumNumerator, uint256 newQuorumNumerator);

    /// @dev Thrown when the provided super quorum numerator is not valid.
    error GovernorInvalidSuperQuorumFraction(uint256 quorumNumerator, uint256 superQuorumDenominator);

    /// @notice Initializes the contract with a super quorum numerator.
    /// @param quorumNumeratorValue The initial super quorum numerator.
    constructor(uint256 quorumNumeratorValue) {
        _updateSuperQuorumNumerator(quorumNumeratorValue);
    }

    /// @notice Returns the current super quorum numerator.
    /// @return The current super quorum numerator value.
    function superQuorumNumerator() public view virtual returns (uint256) {
        return _superQuorumNumeratorHistory.latest();
    }

    /// @notice Gets the super quorum numerator at a specific block timestamp.
    /// @param timepoint The block timestamp for which to get the super quorum numerator.
    /// @return The super quorum numerator at the given timepoint.
    function superQuorumNumerator(uint256 timepoint) public view virtual returns (uint256) {
        return _superQuorumNumeratorHistory.upperLookupRecent(SafeCast.toUint48(timepoint));
    }

    /// @notice Returns the denominator used for calculating the super quorum.
    /// @return The super quorum denominator.
    function superQuorumDenominator() public view virtual returns (uint256) {
        return 100;
    }

    /// @notice Calculates the super quorum required at a given timepoint.
    /// @param timepoint The block timestamp for which to calculate the super quorum.
    /// @return The number of votes required to meet the super quorum at the specified timepoint.
    function superQuorum(uint256 timepoint) public view virtual returns (uint256) {
        return (token().getPastTotalSupply(timepoint) * superQuorumNumerator(timepoint)) / superQuorumDenominator();
    }

    /// @notice Updates the super quorum numerator.
    /// @dev Emits a SuperQuorumNumeratorUpdated event upon success.
    /// @param newQuorumNumerator The new super quorum numerator value.
    function updatesuperQuorumNumerator(uint256 newQuorumNumerator) external virtual onlyGovernance {
        _updateSuperQuorumNumerator(newQuorumNumerator);
    }

    /// @dev Internal function to update the super quorum numerator.
    /// @param newQuorumNumerator The new super quorum numerator value.
    function _updateSuperQuorumNumerator(uint256 newQuorumNumerator) internal virtual {
        if (newQuorumNumerator > superQuorumDenominator()) {
            revert GovernorInvalidSuperQuorumFraction(newQuorumNumerator, superQuorumDenominator());
        }

        uint256 oldQuorumNumerator = superQuorumNumerator();
        _superQuorumNumeratorHistory.push(clock(), SafeCast.toUint208(newQuorumNumerator));

        emit SuperQuorumNumeratorUpdated(oldQuorumNumerator, newQuorumNumerator);
    }
}
