import {
    time,
    mine,
    loadFixture,
    mineUpTo,
} from "@nomicfoundation/hardhat-toolbox/network-helpers";
import { expect } from "chai";
import { ethers } from "hardhat";

// For reference, the enum ProposalState is defined as follows:
// ProposalState {
//    0  Pending,
//    1  Active,
//    2  Canceled,
//    3  Defeated,
//    4  Succeeded,
//    5  Queued,
//    6  Expired,
//    7  Executed
// }

describe("SuperGovernor Contract", function () {
    let SuperGovernor;
    let superGovernor;
    let owner;
    let executionDelay = 0;
    const votingDelay = 2;
    const votingPeriod = 5; // 5 blocks
    const extension = 0;
    const quorumFraction = 10;
    const superQuorumFraction = 60; // 60%
    const proposalThreshold = 0;
    const name = "MyGovernor"

    async function deploySetupFixture() {
        // const superQuorum = 60 //60%
        const [owner, user1] = await ethers.getSigners();
        const token_factory = await ethers.getContractFactory("MyToken");
        const timelock_factory = await ethers.getContractFactory("TimelockController")
        const SuperQuorumGovernor_factory = await ethers.getContractFactory("SuperQuorumGovernor");

        const token = await token_factory.deploy(owner.address);

        const timelock = await timelock_factory.deploy(0, [], [], owner.address);

        const governor = await SuperQuorumGovernor_factory.deploy(
            name,
            await token.getAddress(),
            await timelock.getAddress(),
            votingDelay,
            votingPeriod,
            proposalThreshold,
            quorumFraction,
            superQuorumFraction,
            extension);

        await timelock.grantRole(await timelock.PROPOSER_ROLE(), await governor.getAddress());
        await timelock.grantRole(await timelock.EXECUTOR_ROLE(), await governor.getAddress());

        return { governor, token, timelock, owner, user1 };
    }

    describe("Deployment", function () {
        it("Should deploy with correct governance settings", async function () {
            const { governor, token, timelock, owner } = await loadFixture(deploySetupFixture);

            expect(await governor.votingDelay()).to.equal(votingDelay);
            expect(await governor.votingPeriod()).to.equal(votingPeriod);
            expect(await governor["quorumNumerator()"]()).to.equal(quorumFraction);
        });
    });

    describe("Proposal Lifecycle - Normal Function", function () {
        const proposalDescription = "Proposal #1";

        beforeEach(async function () {
            const { governor, token, timelock, owner, user1 } = await loadFixture(deploySetupFixture);

            this.governor = governor;
            this.token = token;
            this.timelock = timelock;

            // Mint tokens and delegate to owner for voting power
            await token.mint(owner.address, ethers.parseEther("1000"));
            await token.mint(user1.address, ethers.parseEther("9000"));
            await token.delegate(owner.address);
            await token.connect(user1).delegate(user1.address);

            // Create a proposal
            const targets = [owner.address];
            const values = [0];
            const calldatas = [token.interface.encodeFunctionData("mint", [owner.address, ethers.parseEther("1")])];
            await governor.propose(targets, values, calldatas, proposalDescription)

            const prop = await governor.proposalDetailsAt(0);
            this.proposalId = prop[0]
        });

        it("Should be able to cancel before voting period starts", async function () {
            // Initially, the proposal should be in Pending state
            expect(await this.governor.state(this.proposalId)).to.equal(0); // 0 for 'Pending' 

            // Cancel the proposal
            await expect(this.governor.cancel(this.proposalId)).to.emit(this.governor, "ProposalCanceled");

            // Verify the proposal is in Canceled state
            expect(await this.governor.state(this.proposalId)).to.equal(2); // 2 for 'Canceled'
        });



        it("Should transition from Pending to Active when the voting period starts", async function () {
            // Initially, the proposal should be in Pending state
            expect(await this.governor.state(this.proposalId)).to.equal(0); // 0 for 'Pending' 

            // Move to the voting period
            await mine(votingDelay + 1);

            // Verify the proposal is in Active state
            expect(await this.governor.state(this.proposalId)).to.equal(1); // 1 for 'Active'
        });

        it("Should allow voting on a proposal", async function () {
            // Move forward in time to the voting period
            await mine(votingDelay + 1);

            // Vote on the proposal
            await this.governor.castVote(this.proposalId, 1); // 1 for 'For'
            const proposal = await this.governor.proposalVotes(this.proposalId);

            // Verify the new state of the proposal
            expect(await this.governor.state(this.proposalId)).to.equal(1); // 1 for 'Active'
        });

        it("Should process a successful proposal", async function () {
            // Move to the voting period and cast a vote
            await mine(votingDelay + 1);
            await this.governor.castVote(this.proposalId, 1);

            // Move forward in time past the voting period
            await mine(votingPeriod + 1);

            // Check if the proposal was successful
            expect(await this.governor.state(this.proposalId)).to.equal(4); // 4 for 'Succeeded'
        });


        it("Should handle a defeated proposal", async function () {

            // Move to the voting period
            await mine(votingDelay + 1);

            // Move to the voting period and cast a negative vote
            await this.governor.castVote(this.proposalId, 0); // 0 for 'Against'

            // Move forward in time past the voting period
            await mine(votingPeriod + 1);

            // Check if the proposal was defeated
            expect(await this.governor.state(this.proposalId)).to.equal(3); // 3 for 'Defeated'
        });

        it("Should queue a successful proposal", async function () {

            // Move to the voting period
            await mine(votingDelay + 1);

            // Cast a positive vote and end the voting period
            await this.governor.castVote(this.proposalId, 1);
            await mine(votingPeriod + 1);

            // Queue the proposal
            await this.governor.queue(this.proposalId);

            // Verify the proposal is queued
            expect(await this.governor.state(this.proposalId)).to.equal(5); // 5 for 'Queued'
        });

        it("Should succeed when the quorum is met", async function () {

            // Move to the voting period
            await mine(votingDelay + 1);

            // Cast votes meeting/exceeding the quorum requirement
            await this.governor.castVote(this.proposalId, 1); // Assuming this meets the quorum

            // Move forward in time past the voting period
            await mine(votingPeriod + 1);

            // Check if the proposal was successful
            expect(await this.governor.state(this.proposalId)).to.equal(4); // 4 for 'Succeeded'
        });

        it("Should fail when the quorum is not met", async function () {
            // Cast votes, but not enough to meet the quorum
            // await this.governor.castVote(this.proposalId, 1); // Assuming this does not meet the quorum
            // Move to the voting period
            await mine(votingDelay + 1);

            // Move forward in time past the voting period
            await mine(votingPeriod + 1);

            // Check if the proposal was defeated due to not meeting the quorum
            expect(await this.governor.state(this.proposalId)).to.equal(3); // 3 for 'Defeated'
        });

        it("Should queue and execute a successful proposal", async function () {
            // Move to the voting period
            await mine(votingDelay + 1);

            // Cast a positive vote and end the voting period
            await this.governor.castVote(this.proposalId, 1);
            await mine(votingPeriod + 1);

            // Queue the proposal
            await this.governor.queue(this.proposalId);

            // Simulate time delay required before execution
            // Replace 'executionDelay' with your contract's specific delay
            await mine(executionDelay + 1);

            // Execute the proposal
            await this.governor.execute(this.proposalId);

            // Verify the proposal is executed
            expect(await this.governor.state(this.proposalId)).to.equal(7); // 7 for 'Executed'
        });

        it("Should not execute a proposal that has not met the quorum", async function () {
            // Cast insufficient votes, not meeting the quorum
            // await this.governor.castVote(this.proposalId, 1); // Assuming this does not meet the quorum

            // Move forward in time past the voting period
            await mine(votingPeriod + 1);

            // Attempt to queue the proposal
            await expect(this.governor.queue(this.proposalId))
                .to.be.reverted; // Add specific revert reason if your contract has one

            // Attempt to execute the proposal
            await expect(this.governor.execute(this.proposalId))
                .to.be.reverted; // Add specific revert reason if your contract has one
        });

    });

    describe("Proposal Lifecycle - Super Quorum Function", function () {
        const proposalDescription = "Proposal #1";

        beforeEach(async function () {
            const { governor, token, timelock, owner, user1 } = await loadFixture(deploySetupFixture);

            this.governor = governor;
            this.token = token;
            this.timelock = timelock;
            this.owner = owner;
            this.user1 = user1;

            // Mint tokens and delegate to owner for voting power
            await token.mint(owner.address, ethers.parseEther("100"));
            await token.mint(user1.address, ethers.parseEther("9000"));
            await token.delegate(owner.address);
            await token.connect(user1).delegate(user1.address);

            // Create a proposal
            const targets = [owner.address];
            const values = [0];
            const calldatas = [token.interface.encodeFunctionData("mint", [owner.address, ethers.parseEther("1")])];
            await governor.propose(targets, values, calldatas, proposalDescription)

            const prop = await governor.proposalDetailsAt(0);
            this.proposalId = prop[0]

        });


        it("Should not trigger Super Quorum", async function () {
            // Move to the voting period and cast a vote
            await mine(votingDelay + 1);
            await this.governor.castVote(this.proposalId, 1);

            // Move forward in time less than the voting period
            await mine(votingPeriod - 2);

            // Check that proposal is still active
            expect(await this.governor.state(this.proposalId)).to.equal(1); // 1 for 'Active'
        });

        it("Should trigger Super Quorum", async function () {
            // Move to the voting period and cast a vote
            await mine(votingDelay + 1);
            await this.governor.connect(this.user1).castVote(this.proposalId, 1);

            // Move forward in time less than the voting period
            await mine(votingPeriod - 2);

            // Check that proposal succeded
            expect(await this.governor.state(this.proposalId)).to.equal(4); // 4 for 'Succeded'
        });

        it("Should received queued from proposal after we queued it on super quorum before voting periods ends", async function () {
            // Move to the voting period and cast a vote
            await mine(votingDelay + 1);

            // Queue proposal should revert before vote.
            await expect(this.governor.queue(this.proposalId)).to.be.reverted;

            // Vote
            await this.governor.connect(this.user1).castVote(this.proposalId, 1);

            // Queue the proposal
            expect(await this.governor.queue(this.proposalId)).to.emit(this.governor, "ProposalQueued")

            // Verify the proposal is succeeded
            const proposalState = await this.governor.state(this.proposalId);

            // Verify the proposal is queued
            expect(proposalState).to.equal(5); // 5 for 'Queued'
        });

        it("Should not allow votes after super quorum hit", async function () {
            // Move to the voting period and cast a vote
            await mine(votingDelay + 1);
            await this.governor.connect(this.user1).castVote(this.proposalId, 1);

            // Move forward in time less than the voting period
            await mine(votingPeriod - 2);

            // Check that proposal succeded
            expect(await this.governor.state(this.proposalId)).to.equal(4); // 4 for 'Succeded'

            // Make sure you can't vote on it after it's already hit super quorum
            await expect(this.governor.connect(this.owner).castVote(this.proposalId, 1)).to.be.revertedWithCustomError(this.governor, "GovernorUnexpectedProposalState");
        });

        it("Should queue and execute a successful superQuorum proposal", async function () {

            // Move to the voting period
            await mine(votingDelay + 1);

            // Cast a positive vote and end the voting period
            await this.governor.connect(this.user1).castVote(this.proposalId, 1);
            await mine(votingPeriod + 1);

            // Queue the proposal
            await this.governor.queue(this.proposalId);

            // Simulate time delay required before execution
            // Replace 'executionDelay' with your contract's specific delay
            await mine(executionDelay + 1);

            // Execute the proposal
            await this.governor.execute(this.proposalId);

            // Verify the proposal is executed
            expect(await this.governor.state(this.proposalId)).to.equal(7); // 7 for 'Executed'
        });

        it("Should transition from Succeeded to Queued after reaching Super Quorum and being queued", async function () {
            // Move to the voting period and cast votes to reach super quorum
            await mine(votingDelay + 1);
            await this.governor.connect(this.user1).castVote(this.proposalId, 1); // Assume this reaches super quorum

            // Check if the proposal is in Succeeded state
            expect(await this.governor.state(this.proposalId)).to.equal(4); // 4 for 'Succeeded'

            // Queue the proposal
            await this.governor.queue(this.proposalId);

            // Verify the proposal is in Queued state
            expect(await this.governor.state(this.proposalId)).to.equal(5); // 5 for 'Queued'
        });

        it("Should not allow queuing a proposal that is not in Succeeded state", async function () {

            // Attempt to queue the proposal when it's not in Succeeded state
            await expect(this.governor.queue(this.proposalId)).to.be.revertedWithCustomError(this.governor, "GovernorUnexpectedProposalState");
        });


        it("Should remain in Executed state after execution, even if super quorum was met", async function () {
            // Move to the voting period, cast a positive vote to reach super quorum, and end voting period
            await mine(votingDelay + 1);
            await this.governor.connect(this.user1).castVote(this.proposalId, 1); // Assume this reaches super quorum
            await mine(votingPeriod + 1);

            // Queue and execute the proposal
            await this.governor.queue(this.proposalId);
            await mine(executionDelay + 1);
            await this.governor.execute(this.proposalId);

            // Verify the proposal is in Executed state
            expect(await this.governor.state(this.proposalId)).to.equal(7); // 7 for 'Executed'
        });

        it("Should transition from Active to Queued directly when Super Quorum is met and proposal is queued", async function () {
            // Move to the voting period and cast votes to reach super quorum
            await mine(votingDelay + 1);
            await this.governor.connect(this.user1).castVote(this.proposalId, 1); // Assume this reaches super quorum

            // Queue the proposal
            await this.governor.queue(this.proposalId);

            // Verify the proposal is in Queued state
            expect(await this.governor.state(this.proposalId)).to.equal(5); // 5 for 'Queued'
        });

        it("Should transition from Pending to Active when the voting period starts", async function () {
            // Initially, the proposal should be in Pending state
            expect(await this.governor.state(this.proposalId)).to.equal(0); // 0 for 'Pending' 

            // Move to the voting period
            await mine(votingDelay + 1);

            // // Verify the proposal is in Active state
            expect(await this.governor.state(this.proposalId)).to.equal(1); // 1 for 'Active'
        });

        it("Should transition to Defeated state if there are more Against votes", async function () {
            // Move to the voting period and cast an against vote
            await mine(votingDelay + 1);
            await this.governor.castVote(this.proposalId, 0); // 0 for 'Against'

            // Move forward past the voting period
            await mine(votingPeriod + 1);

            // Verify the proposal is in Defeated state
            expect(await this.governor.state(this.proposalId)).to.equal(3); // 3 for 'Defeated'
        });

        it("Should transition to Canceled state if the proposal is canceled", async function () {
            // Cancel the proposal
            await expect(this.governor.connect(this.owner).cancel(this.proposalId)).to.emit(this.governor, "ProposalCanceled").withArgs(this.proposalId);

            // Verify the proposal is in Canceled state
            expect(await this.governor.state(this.proposalId)).to.equal(2); // 2 for 'Canceled'
        });


        it("Should not allow to Cancel when proposal is after votingDelay", async function () {
            await mine(votingDelay + 1);

            // Cancel the proposal
            await expect(this.governor.connect(this.owner).cancel(this.proposalId)).to.be.reverted;

        });

        //NOTE: OZ Timelock controller does not have an expired state natively

        // it("Should transition to Expired state if not executed within time", async function () {
        //     // Move to the voting period, cast a positive vote, end the voting period, and queue the proposal
        //     await mine(votingDelay + 1);
        //     await this.governor.connect(this.owner).castVote(this.proposalId, 1); // 1 for 'For'
        //     await this.governor.connect(this.user1).castVote(this.proposalId, 1); // 1 for 'For'

        //     expect(await this.governor.state(this.proposalId)).to.equal(4); // 4 for 'Succeeded' after super quorum
        //     await mine(votingPeriod+1);

        //     await this.governor.queue(this.proposalId);

        //     // // Simulate passing of execution deadline
        //     // // Replace 'executionDeadline' with your contract's specific deadline
        //     await mine(executionDelay + 1000000 + 1);

        //     // // Verify the proposal is in Expired state
        //     expect(await this.governor.state(this.proposalId)).to.equal(6); // 6 for 'Expired'
        // });

    });


});
