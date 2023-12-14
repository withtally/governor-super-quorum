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

describe("SuperGovernor Contract", function () {
    let SuperGovernor;
    let superGovernor;
    let owner;
    const votingDelay = 0;
    const votingPeriod = 5; // 1 minute
    const quorumFraction = 4;

    async function deploySetupFixture() {
        const superQuorum = 60 //60%
        const [owner] = await ethers.getSigners();
        const token_factory = await ethers.getContractFactory("MyToken");
        const timelock_factory = await ethers.getContractFactory("TimelockController")
        const SuperGovernor_factory = await ethers.getContractFactory("SuperQuorumGovernor");

        const token = await token_factory.deploy(owner.address);

        const timelock = await timelock_factory.deploy(0, [], [], owner.address);

        const governor = await SuperGovernor_factory.deploy(await token.getAddress(), await timelock.getAddress(), superQuorum);

        await timelock.grantRole(await timelock.PROPOSER_ROLE(), await governor.getAddress());

        return { governor, token, timelock, owner };
    }

    describe("Deployment", function () {
        it("Should deploy with correct governance settings", async function () {
            const { governor, token, timelock, owner } = await loadFixture(deploySetupFixture);

            expect(await governor.votingDelay()).to.equal(votingDelay);
            expect(await governor.votingPeriod()).to.equal(votingPeriod);
            expect(await governor["quorumNumerator()"]()).to.equal(quorumFraction);
        });
    });

    describe("Proposal Lifecycle", function () {
        const proposalDescription = "Proposal #1";

        beforeEach(async function () {
            const { governor, token, timelock, owner } = await loadFixture(deploySetupFixture);

            this.governor = governor;
            this.token = token;
            this.timelock = timelock;

            // Mint tokens and delegate to owner for voting power
            await token.mint(owner.address, ethers.parseEther("1000"));
            await token.delegate(owner.address);

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
    });


});
