// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Validator} from "src/validator/Validator.sol";
import {UserOperation} from "src/lib/ERC4337/utils/UserOperation.sol";
import {Operations} from "src/lib/Operations.sol";
import {Access} from "src/access/Access.sol";
import {SignatureChecker} from "openzeppelin-contracts/utils/cryptography/SignatureChecker.sol";
import {ECDSA} from "openzeppelin-contracts/utils/cryptography/ECDSA.sol";

/// @dev Validator module that restricts valid signatures to only come from addresses
/// that have been granted the `CALL_PERMIT` permission in the calling Accounts contract,
/// providing a convenient modular way to manage permissioned private keys
contract CallPermitValidator is Validator {
    constructor(address _entryPointAddress) Validator(_entryPointAddress) {}

    /// @dev Function to enable user operations and comply with `IAccount` interface defined in the EIP-4337 spec
    /// @dev This contract expects signatures in this function's call context to contain a `signer` address
    /// prepended to the ECDSA `nestedSignature`, ie: `abi.encodePacked(address signer, bytes memory nestedSig)`
    /// @param userOp The ERC-4337 user operation, including a `signature` to be recovered and verified
    /// @param userOpHash The hash of the user operation that was signed
    /// @notice The top level call context to an `Account` implementation must prepend
    /// an additional 32-byte word packed with the `VALIDATOR_FLAG` and this address
    function validateUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 /*missingAccountFunds*/ )
        external
        virtual
        returns (uint256 validationData)
    {
        /// @notice BLS sig aggregator and timestamp expiry are not currently supported by this contract
        /// so `bytes20(0x0)` and `bytes6(0x0)` suffice. To enable support for aggregator and timestamp expiry,
        /// override the following params
        bytes20 authorizer;
        bytes6 validUntil;
        bytes6 validAfter;
        uint256 successData = uint256(bytes32(abi.encodePacked(authorizer, validUntil, validAfter)));

        // prepend is 20 since only signer remains prepended after processing validator flag
        uint256 prepend = 20;
        address signer = address(bytes20(userOp.signature[:prepend]));
        bytes calldata nestedSig = userOp.signature[prepend:];

        // terminate if recovered signer address does not match packed signer
        if (!SignatureChecker.isValidSignatureNow(signer, userOpHash, nestedSig)) return SIG_VALIDATION_FAILED;

        // check signer has `Operations::CALL_PERMIT`
        if (Access(msg.sender).hasPermission(Operations.CALL_PERMIT, signer)) {
            validationData = successData;
        } else {
            validationData = SIG_VALIDATION_FAILED;
        }
    }

    /// @dev Function to enable smart contract signature verification and comply with the EIP-1271 spec
    /// @dev This example contract expects signatures in this function's call context
    /// to contain a `signer` address prepended to the ECDSA `nestedSignature`
    /// @param msgHash The hash of the message signed
    /// @param signature The signature to be recovered and verified
    /// @notice The top level call context to an `Account` implementation must prepend
    /// an additional 32-byte word packed with the `VALIDATOR_FLAG` and this address
    function isValidSignature(bytes32 msgHash, bytes calldata signature)
        external
        view
        virtual
        returns (bytes4 magicValue)
    {
        // prepend is 20 since only signer remains prepended after processing validator flag
        uint256 prepend = 20;
        address signer = address(bytes20(signature[:prepend]));
        bytes calldata nestedSig = signature[prepend:];

        // use SignatureChecker to evaluate `signer` and `nestedSig`
        bool validSig = SignatureChecker.isValidSignatureNow(signer, msgHash, nestedSig);

        // check signer has `Operations::CALL_PERMIT`
        if (validSig && Access(msg.sender).hasPermission(Operations.CALL_PERMIT, signer)) {
            magicValue = this.isValidSignature.selector;
        } else {
            magicValue = INVALID_SIGNER;
        }
    }
}
