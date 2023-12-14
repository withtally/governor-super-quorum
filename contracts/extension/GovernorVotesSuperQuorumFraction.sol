// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts (last updated v5.0.0) (governance/extensions/GovernorVotesQuorumFraction.sol)

pragma solidity ^0.8.20;

import {GovernorVotes} from "@openzeppelin/contracts/governance/extensions/GovernorVotes.sol";
import { SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";
import {Checkpoints} from "@openzeppelin/contracts/utils/structs/Checkpoints.sol";

/**
 * @dev Extension of {Governor} for voting weight extraction from an {ERC20Votes} token and a quorum expressed as a
 * fraction of the total supply.
 */
abstract contract GovernorVotesSuperQuorumFraction is GovernorVotes {
    using Checkpoints for Checkpoints.Trace208;

    Checkpoints.Trace208 private _superQuorumNumeratorHistory;

    event SuperQuorumNumeratorUpdated(uint256 oldQuorumNumerator, uint256 newQuorumNumerator);

    /**
     * @dev The quorum set is not a valid fraction.
     */
    error GovernorInvalidSuperQuorumFraction(uint256 quorumNumerator, uint256 superQuorumDenominator);

    /**
     * @dev Initialize quorum as a fraction of the token's total supply.
     *
     * The fraction is specified as `numerator / denominator`. By default the denominator is 100, so quorum is
     * specified as a percent: a numerator of 10 corresponds to quorum being 10% of total supply. The denominator can be
     * customized by overriding {superQuorumDenominator}.
     */
    constructor(uint256 quorumNumeratorValue) {
        _updateSuperQuorumNumerator(quorumNumeratorValue);
    }




    /**
     * @dev Returns the current quorum numerator. See {superQuorumDenominator}.
     */
    function superQuorumNumerator() public view virtual returns (uint256) {
        return _superQuorumNumeratorHistory.latest();
    }

    /**
     * @dev Returns the quorum numerator at a specific timepoint. See {superQuorumDenominator}.
     */
    function superQuorumNumerator(uint256 timepoint) public view virtual returns (uint256) {
        uint256 length = _superQuorumNumeratorHistory._checkpoints.length;

        // Optimistic search, check the latest checkpoint
        Checkpoints.Checkpoint208 storage latest = _superQuorumNumeratorHistory._checkpoints[length - 1];
        uint48 latestKey = latest._key;
        uint208 latestValue = latest._value;
        if (latestKey <= timepoint) {
            return latestValue;
        }

        // Otherwise, do the binary search
        return _superQuorumNumeratorHistory.upperLookupRecent(SafeCast.toUint48(timepoint));
    }

    /**
     * @dev Returns the quorum denominator. Defaults to 100, but may be overridden.
     */
    function superQuorumDenominator() public view virtual returns (uint256) {
        return 100;
    }

    /**
     * @dev Returns the quorum for a timepoint, in terms of number of votes: `supply * numerator / denominator`.
     */
    function superQuorum(uint256 timepoint) public view virtual returns (uint256) {
        return (token().getPastTotalSupply(timepoint) * superQuorumNumerator(timepoint)) / superQuorumDenominator();
    }

    /**
     * @dev Changes the quorum numerator.
     *
     * Emits a {SuperQuorumNumeratorUpdated} event.
     *
     * Requirements:
     *
     * - Must be called through a governance proposal.
     * - New numerator must be smaller or equal to the denominator.
     */
    function updatesuperQuorumNumerator(uint256 newQuorumNumerator) external virtual onlyGovernance {
        _updateSuperQuorumNumerator(newQuorumNumerator);
    }

    /**
     * @dev Changes the quorum numerator.
     *
     * Emits a {SuperQuorumNumeratorUpdated} event.
     *
     * Requirements:
     *
     * - New numerator must be smaller or equal to the denominator.
     */
    function _updateSuperQuorumNumerator(uint256 newQuorumNumerator) internal virtual {
        uint256 denominator = superQuorumDenominator();
        if (newQuorumNumerator > denominator) {
            revert GovernorInvalidSuperQuorumFraction(newQuorumNumerator, denominator);
        }

        uint256 oldQuorumNumerator = superQuorumNumerator();
        _superQuorumNumeratorHistory.push(clock(), SafeCast.toUint208(newQuorumNumerator));

        emit SuperQuorumNumeratorUpdated(oldQuorumNumerator, newQuorumNumerator);
    }
}
