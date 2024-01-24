import { expect } from "chai";
import { ethers } from "hardhat";
import { SetupFixtureReturnType } from "./types";

export async function deployUpgradableSetupFixture(): Promise<SetupFixtureReturnType> {

    let executionDelay = 0;
    const votingDelay = 2;
    const votingPeriod = 5; // 5 blocks
    const extension = 0;
    const quorumFraction = 10;
    const superQuorumFraction = 60; // 60%
    const proposalThreshold = 0;
    const name = "MyGovernor"


    // const superQuorum = 60 //60%
    const [owner, user1] = await ethers.getSigners();
    const token_factory = await ethers.getContractFactory("MyToken");
    const timelock_factory = await ethers.getContractFactory("TimelockUpgradeable")
    const SuperQuorumGovernor_factory = await ethers.getContractFactory("SuperQuorumGovernorUpgradeable");

    const token = await token_factory.deploy(owner.address);

    const timelock = await timelock_factory.deploy();

    await timelock.initialize(0, [], [], owner.address);

    const governor = await SuperQuorumGovernor_factory.deploy();

    await governor.initialize(name,
        await token.getAddress(),
        await timelock.getAddress(),
        votingDelay,
        votingPeriod,
        proposalThreshold,
        quorumFraction,
        superQuorumFraction,
        extension)

    await timelock.grantRole(await timelock.PROPOSER_ROLE(), await governor.getAddress());
    await timelock.grantRole(await timelock.EXECUTOR_ROLE(), await governor.getAddress());

    return { governor, token, timelock, owner, user1, executionDelay, votingDelay, votingPeriod, extension, quorumFraction, superQuorumFraction, proposalThreshold, name };
}

export async function deployNormalSetupFixture() {
    let executionDelay = 0;
    const votingDelay = 2;
    const votingPeriod = 5; // 5 blocks
    const extension = 0;
    const quorumFraction = 10;
    const superQuorumFraction = 60; // 60%
    const proposalThreshold = 0;
    const name = "MyGovernor"

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

    return { governor, token, timelock, owner, user1, executionDelay, votingDelay, votingPeriod, extension, quorumFraction, superQuorumFraction, proposalThreshold, name };

}
