

import { shouldDeploy, shouldDoProposalLifecycle, shouldDoSuperQuorumProposalLifecycle, shouldInitialize } from "./behavior.test";
import { deployUpgradableSetupFixture } from "./fixtures";


describe("SuperGovernor Contract Upgradeable", function () {


    shouldDeploy(deployUpgradableSetupFixture)
    shouldInitialize(deployUpgradableSetupFixture)
    shouldDoProposalLifecycle(deployUpgradableSetupFixture)
    shouldDoSuperQuorumProposalLifecycle(deployUpgradableSetupFixture)


});
