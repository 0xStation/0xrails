// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

abstract contract MetadataRouterExtensionData {
    function _getMetadataRouter() internal view returns (address) {
        MetadataRouterStorage.Data storage data = MetadataRouterStorage.read();
        return data.metadataRouter;
    }
}

library MetadataRouterStorage {
    bytes32 public constant STORAGE_POSITION =
        keccak256(abi.encode(uint256(keccak256("0xrails.Extensions.MetadataRouterData")) - 1));

    struct Data {
        address metadataRouter;
    }

    function read() internal pure returns (Data storage data) {
        bytes32 position = STORAGE_POSITION;
        assembly {
            data.slot := position
        }
    }
}
