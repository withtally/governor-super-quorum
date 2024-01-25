// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/proxy/Clones.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";

contract Factory is AccessControl, Initializable {
    bytes32 public constant UPDATER_ROLE = keccak256("UPDATER_ROLE");

    // Address of the implementation contract
    address public implementation;

    error InitializationFailed();
    error InvalidImplementationAddress();

    // Event to announce the implementation address stored
    event ImplementationStored(address indexed implementation);

    // Event to announce a new clone was created
    event CloneCreated(address indexed cloneAddress);

    // TODO Consider Roles here
    // Initializer function to set the initial implementation address
    function initialize(address _implementation, address _admin) public initializer {
        _grantRole(DEFAULT_ADMIN_ROLE, _admin);
        _grantRole(UPDATER_ROLE, _admin);
        _setImplementation(_implementation);
    }

    // Function to update the implementation contract address
    function updateImplementation(
        address newImplementation
    ) public onlyRole(UPDATER_ROLE) {
        _setImplementation(newImplementation);
    }

    // Internal function to set the implementation address
    function _setImplementation(address newImplementation) internal {
        if (newImplementation == address(0))
            revert InvalidImplementationAddress();
        implementation = newImplementation;
        emit ImplementationStored(newImplementation);
    }

    // Function to clone and initialize a new contract
    function cloneAndInitialize(
        bytes calldata initData
    ) public returns (address) {
        address clone = Clones.clone(implementation);
        (bool success, ) = clone.call(initData);

        if (!success) revert InitializationFailed();
        emit CloneCreated(clone);
        return clone;
    }
}
