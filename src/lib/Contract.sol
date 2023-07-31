// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Address} from "lib/openzeppelin-contracts/contracts/utils/Address.sol";

abstract contract Contract {
    error InvalidContract(address implementation);

    function _requireContract(address implementation) internal view {
        if (!Address.isContract(implementation)) revert InvalidContract(implementation);
    }
}
