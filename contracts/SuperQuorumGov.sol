// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/governance/Governor.sol";
import "@openzeppelin/contracts/governance/extensions/GovernorSettings.sol";
import "@openzeppelin/contracts/governance/extensions/GovernorCountingSimple.sol";
import "@openzeppelin/contracts/governance/extensions/GovernorStorage.sol";
import "@openzeppelin/contracts/governance/extensions/GovernorVotes.sol";
import "@openzeppelin/contracts/governance/extensions/GovernorVotesQuorumFraction.sol";
import "@openzeppelin/contracts/governance/extensions/GovernorTimelockControl.sol";

contract SuperQuorumGovernor is
    Governor,
    GovernorSettings,
    GovernorCountingSimple,
    GovernorStorage,
    GovernorVotes,
    GovernorVotesQuorumFraction,
    GovernorTimelockControl
{
    uint256 private _superQuorumThreshold;

    constructor(
        IVotes _token,
        TimelockController _timelock,
        uint256 superQuorumThreshold
    )
        Governor("MyGovernor")
        GovernorSettings(0,5,0)
        GovernorVotes(_token)
        GovernorVotesQuorumFraction(4)
        GovernorTimelockControl(_timelock)
    {
        _superQuorumThreshold = superQuorumThreshold;
    }

    // Override for SuperQuorum

    // // override the _quorumReached function to return yes for superQuorum
    // function _quorumReached(
    //     uint256 proposalId
    // ) internal view override(Governor, GovernorCountingSimple) returns (bool) {
    //     ProposalVote storage proposalVote = _proposalVotes[proposalId];

    //     return
    //         quorum(proposalSnapshot(proposalId)) <=
    //         proposalVote.forVotes + proposalVote.abstainVotes ||
    //         proposalVote.forVotes >= _superQuorumThreshold;
    // }

    // // override the state function to allow voting for superQuorum
    // function state(
    //     uint256 proposalId
    // )
    //     public
    //     view
    //     override(Governor, GovernorTimelockControl)
    //     returns (ProposalState)
    // {
    //     // We read the struct fields into the stack at once so Solidity emits a single SLOAD
    //     ProposalCore storage proposal = _proposals[proposalId];
    //     bool proposalExecuted = proposal.executed;
    //     bool proposalCanceled = proposal.canceled;

    //     if (proposalExecuted) {
    //         return ProposalState.Executed;
    //     }

    //     if (proposalCanceled) {
    //         return ProposalState.Canceled;
    //     }

    //     uint256 snapshot = proposalSnapshot(proposalId);

    //     if (snapshot == 0) {
    //         revert GovernorNonexistentProposal(proposalId);
    //     }

    //     uint256 currentTimepoint = clock();

    //     if (snapshot >= currentTimepoint) {
    //         return ProposalState.Pending;
    //     }

    //     uint256 deadline = proposalDeadline(proposalId);

    //     //Return success if the proposal has passed the superQuorumThreshold
    //     if (proposal.forVotes >= _superQuorumThreshold) {
    //         return ProposalState.Succeeded;
    //     }

    //     if (deadline >= currentTimepoint) {
    //         return ProposalState.Active;
    //     } else if (!_quorumReached(proposalId) || !_voteSucceeded(proposalId)) {
    //         return ProposalState.Defeated;
    //     } else if (proposalEta(proposalId) == 0) {
    //         return ProposalState.Succeeded;
    //     } else {
    //         return ProposalState.Queued;
    //     }
    // }

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

    function state(
        uint256 proposalId
    )
        public
        view
        override(Governor, GovernorTimelockControl)
        returns (ProposalState)
    {
        return super.state(proposalId);
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
