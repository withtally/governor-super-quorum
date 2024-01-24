
import type { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/dist/src/signer-with-address";


import { Governor, MyToken, TimelockController, TimelockControllerUpgradeable, GovernorUpgradeable, SuperQuorumGovernorUpgradeable, SuperQuorumGovernor } from "../typechain-types";

export interface SetupFixtureReturnType {
    governor: SuperQuorumGovernor | SuperQuorumGovernorUpgradeable;
    token: MyToken;
    timelock: TimelockController | TimelockControllerUpgradeable;
    owner: SignerWithAddress;
    user1: SignerWithAddress;
    executionDelay: number;
    votingDelay: number;
    votingPeriod: number;
    extension: number;
    quorumFraction: number;
    superQuorumFraction: number;
    proposalThreshold: number;
    name: string;
}
