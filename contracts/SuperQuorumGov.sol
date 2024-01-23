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
    
    /**
     * @dev Initializes the OZGovernor contract.
     * @param _name The name of the governor.
     * @param _token The voting token.
     * @param _timelock The timelock controller.
     * @param _initialVotingDelay, 7200, 1 day
     * @param _initialVotingPeriod, 50400, 1 week 
     * @param _initialProposalThreshold, 0, proposal threshold
     * @param _quorumNumeratorValue, 4, numerator value for quorum
     * @param _superQuorumThreshold, minimum number of votes required for super quorum,
     * @param _initialVoteExtension,
     */
    constructor(
        string memory _name, IVotes _token, TimelockController _timelock,
        uint48 _initialVotingDelay, uint32 _initialVotingPeriod, uint256 _initialProposalThreshold,
        uint256 _quorumNumeratorValue,   
        uint32 _superQuorumThreshold,     
        uint48 _initialVoteExtension
    )
        Governor(_name)
        GovernorSettings(_initialVotingDelay, _initialVotingPeriod, _initialProposalThreshold)
        GovernorVotes(_token)
        GovernorVotesQuorumFraction(_quorumNumeratorValue)
        GovernorPreventLateQuorum(_initialVoteExtension)
        GovernorVotesSuperQuorumFraction(_superQuorumThreshold)
        GovernorTimelockControl(_timelock)
    {}

    /// @notice Returns the current state of a proposal.
    /// @dev Overridden to include logic for handling super quorum.
    /// @param proposalId The ID of the proposal.
    /// @return Current state of the proposal.
    function state(
        uint256 proposalId
    )
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

        // This overrides how succeeded is calculated only if we're over superquorum
        if (
            proposalState == ProposalState.Active &&
            (superQuorum(proposalSnapshot(proposalId)) <=
                forVotes + abstainVotes)
        ) {
            if(proposalEta(proposalId) != 0){
                return ProposalState.Queued;
            }
            return ProposalState.Succeeded;
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
