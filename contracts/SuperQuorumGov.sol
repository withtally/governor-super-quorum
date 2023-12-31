// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/governance/Governor.sol";
import "@openzeppelin/contracts/governance/extensions/GovernorSettings.sol";
import "@openzeppelin/contracts/governance/extensions/GovernorCountingSimple.sol";
import "@openzeppelin/contracts/governance/extensions/GovernorStorage.sol";
import "@openzeppelin/contracts/governance/extensions/GovernorVotes.sol";
import "@openzeppelin/contracts/governance/extensions/GovernorVotesQuorumFraction.sol";
import "@openzeppelin/contracts/governance/extensions/GovernorTimelockControl.sol";
import "@openzeppelin/contracts/governance/extensions/GovernorPreventLateQuorum.sol";
import "./extension/GovernorVotesSuperQuorumFraction.sol";

/// @title SuperQuorumGovernor
/// @dev Extends OpenZeppelin's Governor contract with super quorum functionality.
contract SuperQuorumGovernor is
    Governor,
    GovernorSettings,
    GovernorCountingSimple,
    GovernorStorage,
    GovernorVotes,
    GovernorVotesQuorumFraction,
    GovernorVotesSuperQuorumFraction,
    GovernorPreventLateQuorum,
    GovernorTimelockControl
{
    uint256 private _superQuorumThreshold;
    
    /// @dev Initializes the governor contract with custom settings.
    /// @param _token Address of the governance token.
    /// @param _timelock Address of the timelock controller.
    /// @param superQuorumThreshold Threshold for the super quorum.
    /// @param _votingPeriod Duration of the voting period.
    /// @param _votingDelay Delay before voting on a proposal starts.
    /// @param _proposalThreshold Minimum number of tokens required to create a proposal.
    /// @param _initialVoteExtension Initial vote extension duration.
    constructor(
        IVotes _token,
        TimelockController _timelock,
        uint256 superQuorumThreshold,
        uint32 _votingPeriod,
        uint48 _votingDelay,
        uint256 _proposalThreshold,
        uint32 _initialVoteExtension
    )
        Governor("MyGovernor")
        GovernorSettings(_votingDelay, _votingPeriod, _proposalThreshold)
        GovernorVotes(_token)
        GovernorVotesQuorumFraction(10)
        GovernorVotesSuperQuorumFraction(50)
        GovernorTimelockControl(_timelock)
        GovernorPreventLateQuorum(_initialVoteExtension)
    {}

function state(uint256 proposalId)
    public
    view
    override(Governor, GovernorTimelockControl)
    returns (ProposalState)
{
    ProposalState proposalState = super.state(proposalId);

    (
        uint256 againstVotes,
        uint256 forVotes,
        uint256 abstainVotes
    ) = proposalVotes(proposalId);

    bool hasReachedSuperQuorum = superQuorum(proposalSnapshot(proposalId)) <= forVotes + abstainVotes;

    // Adjusted logic to properly reflect 'Queued' state for Super Quorum proposals.
    if (proposalState == ProposalState.Active && hasReachedSuperQuorum) {
        // If a proposal has reached super quorum and is queued, it should be in 'Queued' state.
        if (proposalEta(proposalId) != 0) {
            return ProposalState.Queued;
        }
        return ProposalState.Succeeded;
    }

    // The rest of the logic remains unchanged.
    if (proposalState == ProposalState.Executed) {
        return ProposalState.Executed;
    } else if (proposalState == ProposalState.Succeeded) {
        if (proposalEta(proposalId) != 0) {
            return ProposalState.Queued;
        }
    }

    return proposalState;
}


    // The following functions are overrides required by Solidity.

    function votingDelay()
        public
        view
        override(Governor, GovernorSettings)
        returns (uint256)
    {
        return super.votingDelay();
    }

    function votingPeriod()
        public
        view
        override(Governor, GovernorSettings)
        returns (uint256)
    {
        return super.votingPeriod();
    }

    function quorum(
        uint256 blockNumber
    )
        public
        view
        override(Governor, GovernorVotesQuorumFraction)
        returns (uint256)
    {
        return super.quorum(blockNumber);
    }

    function proposalNeedsQueuing(
        uint256 proposalId
    ) public view override(Governor, GovernorTimelockControl) returns (bool) {
        return super.proposalNeedsQueuing(proposalId);
    }

    function proposalThreshold()
        public
        view
        override(Governor, GovernorSettings)
        returns (uint256)
    {
        return super.proposalThreshold();
    }

    function _propose(
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory calldatas,
        string memory description,
        address proposer
    ) internal override(Governor, GovernorStorage) returns (uint256) {
        return
            super._propose(targets, values, calldatas, description, proposer);
    }

    function _queueOperations(
        uint256 proposalId,
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory calldatas,
        bytes32 descriptionHash
    ) internal override(Governor, GovernorTimelockControl) returns (uint48) {
        return
            super._queueOperations(
                proposalId,
                targets,
                values,
                calldatas,
                descriptionHash
            );
    }

    function _executeOperations(
        uint256 proposalId,
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory calldatas,
        bytes32 descriptionHash
    ) internal override(Governor, GovernorTimelockControl) {
        super._executeOperations(
            proposalId,
            targets,
            values,
            calldatas,
            descriptionHash
        );
    }

    /**
     * @notice Casts a vote on a proposal.
     * @param proposalId The ID of the proposal to vote on.
     * @param account The address of the voter.
     * @param support The vote choice (true for yes, false for no).
     * @param reason A brief description of the reason for the vote.
     * @param params The parameters for the vote.
     * @return The ID of the vote.
     */
    function _castVote(
        uint256 proposalId,
        address account,
        uint8 support,
        string memory reason,
        bytes memory params
    )
        internal
        virtual
        override(Governor, GovernorPreventLateQuorum)
        returns (uint256)
    {
        return super._castVote(proposalId, account, support, reason, params);
    }

    /**
     *
     * @notice Retrieves the deadline for submitting proposals.
     * @param proposalId The ID of the proposal to query.
     * @return The deadline for submitting proposals.
     */
    function proposalDeadline(
        uint256 proposalId
    )
        public
        view
        override(Governor, GovernorPreventLateQuorum)
        returns (uint256)
    {
        return super.proposalDeadline(proposalId);
    }

    function _cancel(
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory calldatas,
        bytes32 descriptionHash
    ) internal override(Governor, GovernorTimelockControl) returns (uint256) {
        return super._cancel(targets, values, calldatas, descriptionHash);
    }

    function _executor()
        internal
        view
        override(Governor, GovernorTimelockControl)
        returns (address)
    {
        return super._executor();
    }
}
