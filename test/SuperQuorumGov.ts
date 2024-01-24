
import { shouldDeploy, shouldDoProposalLifecycle, shouldDoSuperQuorumProposalLifecycle } from "./behavior.test";
import { deployNormalSetupFixture } from "./fixtures";


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

    shouldDeploy(deployNormalSetupFixture)
    shouldDoProposalLifecycle(deployNormalSetupFixture)
    shouldDoSuperQuorumProposalLifecycle(deployNormalSetupFixture)

});
