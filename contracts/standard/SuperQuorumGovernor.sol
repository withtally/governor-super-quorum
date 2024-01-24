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

    // TODO: Take in params via array to pass VIA IR
    /**
     * @dev Initializes the OZGovernor contract.
     * @param _name The name of the governor.
     * @param _token The voting token.
     * @param _timelock The timelock controller.
     * @param voteDelayAndExtension, An array to bypass stack too deep error: [_initialVotingDelay _initialVoteExtension]
     * @param _initialVotingPeriod, 50400, 1 week
     * @param _initialProposalThreshold, 0, proposal threshold
     * @param _quorumNumeratorValue, 4, numerator value for quorum
     * @param _superQuorumNumerator, minimum number of votes required for super quorum,
     */
    constructor(
        string memory _name,
        IVotes _token,
        TimelockController _timelock,
        uint48[] memory voteDelayAndExtension, //  [_initialVotingDelay _initialVoteExtension]
        uint32 _initialVotingPeriod,
        uint256 _initialProposalThreshold,
        uint256 _quorumNumeratorValue,
        uint32 _superQuorumNumerator
    )
        Governor(_name)
        GovernorSettings(
            voteDelayAndExtension[0],
            _initialVotingPeriod,
            _initialProposalThreshold
        )
        GovernorVotes(_token)
        GovernorVotesQuorumFraction(_quorumNumeratorValue)
        GovernorPreventLateQuorum(voteDelayAndExtension[1])
        GovernorVotesSuperQuorumFraction(_superQuorumNumerator)
        GovernorTimelockControl(_timelock)
    {}

    /**
     * @notice Retrieves the voting delay configured in the settings.
     * @return The configured voting delay.
     */
    function votingDelay()
        public
        view
        override(Governor, GovernorSettings)
        returns (uint256)
    {
        return super.votingDelay();
    }

    /**
     * @notice Retrieves the voting period configured in the settings.
     * @return The configured voting period.
     */
    function votingPeriod()
        public
        view
        override(Governor, GovernorSettings)
        returns (uint256)
    {
        return super.votingPeriod();
    }

    /**
     * @notice Retrieves the quorum required for a vote to succeed.
     * @param blockNumber The block number for which to determine the quorum.
     * @return The required quorum at the given block number.
     */
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
            // solhint-disable-next-line
            uint256 againstVotes, //compiler complains because it's unused
            uint256 forVotes,
            // solhint-disable-next-line
            uint256 abstainVotes //compiler complains because it's unused
        ) = proposalVotes(proposalId);

        // This overrides how succeeded is calculated only if we're over superquorum
        if (
            proposalState == ProposalState.Active &&
            (superQuorum(proposalSnapshot(proposalId)) <=
                forVotes) // NOTE: we're not including abstain in super quorum
        ) {
            if (proposalEta(proposalId) != 0) {
                return ProposalState.Queued;
            }
            return ProposalState.Succeeded;
        }

        return proposalState;
    }

    /**
     * @notice Checks if a proposal needs to be queued.
     * @param proposalId The ID of the proposal to check.
     * @return A boolean indicating whether the proposal needs to be queued.
     */
    function proposalNeedsQueuing(
        uint256 proposalId
    ) public view override(Governor, GovernorTimelockControl) returns (bool) {
        return super.proposalNeedsQueuing(proposalId);
    }

    /**
     * @notice Retrieves the threshold required for a proposal to be enacted.
     * @return The threshold required for a proposal to be enacted.
     */
    function proposalThreshold()
        public
        view
        override(Governor, GovernorSettings)
        returns (uint256)
    {
        return super.proposalThreshold();
    }

    /**
     * @notice Proposes an action to be taken.
     * @param targets The addresses of the contracts to interact with.
     * @param values The values (ETH) to send in the interactions.
     * @param calldatas The encoded data of the interactions.
     * @param description A brief description of the proposal.
     * @param proposer The address of the proposer.
     * @return The ID of the newly created proposal.
     */
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

    /**
     * @notice Queues operations for execution.
     * @param proposalId The ID of the proposal containing the operations.
     * @param targets The addresses of the contracts to interact with.
     * @param values The values (ETH) to send in the interactions.
     * @param calldatas The encoded data of the interactions.
     * @param descriptionHash The hash of the proposal description.
     * @return The ID of the timelock transaction.
     */
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

    /**
     * @notice Executes operations from a proposal.
     * @param proposalId The ID of the proposal containing the operations.
     * @param targets The addresses of the contracts to interact with.
     * @param values The values (ETH) to send in the interactions.
     * @param calldatas The encoded data of the interactions.
     * @param descriptionHash The hash of the proposal description.
     */
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
     * @notice Cancels operations from a proposal.
     * @param targets The addresses of the contracts to interact with.
     * @param values The values (ETH) to send in the interactions.
     * @param calldatas The encoded data of the interactions.
     * @param descriptionHash The hash of the proposal description.
     * @return The ID of the canceled proposal.
     */
    function _cancel(
        address[] memory targets,
        uint256[] memory values,
        bytes[] memory calldatas,
        bytes32 descriptionHash
    ) internal override(Governor, GovernorTimelockControl) returns (uint256) {
        return super._cancel(targets, values, calldatas, descriptionHash);
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

    /**
     * @notice Retrieves the address of the executor configured in the timelock control.
     * @return The address of the executor.
     */
    function _executor()
        internal
        view
        override(Governor, GovernorTimelockControl)
        returns (address)
    {
        return super._executor();
    }
}
