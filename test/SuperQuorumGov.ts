import {
    time,
    mine,
    loadFixture,
    mineUpTo,
} from "@nomicfoundation/hardhat-toolbox/network-helpers";
import { anyValue } from "@nomicfoundation/hardhat-chai-matchers/withArgs";
import { expect } from "chai";
import { ethers } from "hardhat";
import { Governor } from "../typechain-types";

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
    const votingDelay = 0;
    const votingPeriod = 5; // 5 blocks
    const quorumFraction = 10;
    const superQuorumFraction = 50;

    async function deploySetupFixture() {
        const superQuorum = 60 //60%
        const [owner, user1] = await ethers.getSigners();
        const token_factory = await ethers.getContractFactory("MyToken");
        const timelock_factory = await ethers.getContractFactory("TimelockController")
        const SuperGovernor_factory = await ethers.getContractFactory("SuperQuorumGovernor");

        const token = await token_factory.deploy(owner.address);

        const timelock = await timelock_factory.deploy(0, [], [], owner.address);

        const governor = await SuperGovernor_factory.deploy(await token.getAddress(), await timelock.getAddress(), superQuorum, votingPeriod, votingDelay, 0);

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
            // Move to the voting period and cast a negative vote
            await this.governor.castVote(this.proposalId, 0); // 0 for 'Against'

            // Move forward in time past the voting period
            await mine(votingPeriod + 1);

            // Check if the proposal was defeated
            expect(await this.governor.state(this.proposalId)).to.equal(3); // 3 for 'Defeated'
        });

        it("Should queue a successful proposal", async function () {
            // Cast a positive vote and end the voting period
            await this.governor.castVote(this.proposalId, 1);
            await mine(votingPeriod + 1);

            // Queue the proposal
            await this.governor.queue(this.proposalId);

            // Verify the proposal is queued
            expect(await this.governor.state(this.proposalId)).to.equal(5); // 5 for 'Queued'
        });

        it("Should succeed when the quorum is met", async function () {
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

            // Move forward in time past the voting period
            await mine(votingPeriod + 1);

            // Check if the proposal was defeated due to not meeting the quorum
            expect(await this.governor.state(this.proposalId)).to.equal(3); // 3 for 'Defeated'
        });

        it("Should queue and execute a successful proposal", async function () {
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

        it("Should queue and execute a successful superQuorum proposal", async function () {
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


    });


});
