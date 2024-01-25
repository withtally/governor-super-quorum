import { ethers } from 'hardhat';
import { expect } from 'chai';
import { Contract, Signer } from 'ethers';
import { Factory, MyToken } from '../../typechain-types'; // Adjust the path according to your project structure



describe('Factory Contract Tests', () => {

    // Factory variables
    let factory: Factory;
    let signers: Signer[];
    let admin: Signer;
    let updater: Signer;
    let mockAddress: Signer;
    let implementationAddress: string;
    let implementation2Address: string;
    let encodedData: string;

    //SuperQuorumGovernor Variables
    let executionDelay = 0;
    const votingDelay = 2;
    const votingPeriod = 5; // 5 blocks
    const extension = 0;
    const quorumFraction = 10;
    const superQuorumFraction = 60; // 60%
    const proposalThreshold = 0;
    const name = "MyGovernor"

    // Fixture to deploy the contract and set initial state
    async function deployFactoryFixture() {
        signers = await ethers.getSigners();
        [admin, updater, mockAddress] = signers;

        const FactoryContract = await ethers.getContractFactory('Factory');
        factory = await FactoryContract.deploy() as Factory;

        // Deploy a mock implementation contract and set it in the factory
        const ImplementationContract = await ethers.getContractFactory('SuperQuorumGovernorUpgradeable');
        const token_factory = await ethers.getContractFactory("MyToken");
        const timelock_factory = await ethers.getContractFactory("TimelockUpgradeable")
        const token = await token_factory.deploy(admin.address);
        const timelock = await timelock_factory.deploy();
        await timelock.initialize(0, [], [], admin.address);


        const implementation = await ImplementationContract.deploy();
        const implementation2 = await ImplementationContract.deploy();

        implementationAddress = await implementation.getAddress();
        implementation2Address = await implementation2.getAddress();

        await factory.initialize(implementationAddress, await updater.getAddress());

        encodedData = implementation.interface.encodeFunctionData("initialize",
            [name, await token.getAddress(),
                await timelock.getAddress(),
                [votingDelay, extension],
                votingPeriod,
                proposalThreshold,
                quorumFraction,
                superQuorumFraction,
            ])

        return { factory, implementation, implementation2, admin, updater, encodedData };
    }


    it('should deploy clone', async () => {
        const { factory, admin, encodedData } = await deployFactoryFixture();

        // Deploy a clone
        const tx = await factory.connect(admin).cloneAndInitialize(encodedData);
        await tx.wait();

        // Retrieve the event
        const events = await factory.queryFilter(factory.filters['CloneCreated(address)']());

        // Check if the event is present and has the correct argument
        expect(events).to.not.be.empty;

        const event = events[events.length - 1];
        const clonedAddress = event.args.cloneAddress;

        // Check if the clone is initialized
        const clonedContract = await ethers.getContractAt('SuperQuorumGovernorUpgradeable', clonedAddress);
        expect(await clonedContract.name()).to.equal(name);

    });

    it('should emit ImplementationStored event with correct address', async () => {
        const { factory, admin } = await deployFactoryFixture();

        // Trigger the event
        const tx = await factory.connect(updater).updateImplementation(implementation2Address);
        await tx.wait();

        // Retrieve the event
        const events = await factory.queryFilter(factory.filters.ImplementationStored());

        // Check if the event is present and has the correct argument
        expect(events).to.not.be.empty;
        const event = events[events.length - 1];
        expect(event.args.implementation).to.equal(implementation2Address);
    });


    it('should update implementation address', async () => {
        const newImplementationAddress = "0x70ebAD30a31657A9cF7A748269C2FB0E63C2E4B7";
        await expect(factory.connect(updater).updateImplementation(newImplementationAddress))
            .to.emit(factory, 'ImplementationStored')
            .withArgs(newImplementationAddress);

        expect(await factory.implementation()).to.equal(newImplementationAddress);
    });

    // ... (more tests)


});
