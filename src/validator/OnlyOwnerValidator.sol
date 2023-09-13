// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Validator} from "src/validator/Validator.sol";
import {UserOperation} from "src/lib/ERC4337/utils/UserOperation.sol";
import {Ownable} from "src/access/ownable/Ownable.sol";
import {ECDSA} from "openzeppelin-contracts/utils/cryptography/ECDSA.sol";
import {SignatureChecker} from "openzeppelin-contracts/utils/cryptography/SignatureChecker.sol";

/// @dev Example Validator module that restricts valid signatures to only come from the owner
/// of the calling Accounts contract 
contract OnlyOwnerValidator is Validator {

    constructor(address _entryPointAddress) Validator(_entryPointAddress) {}

    /// @dev This example contract would only be forwarded signatures formatted as follows:
    /// `abi.encode(address signer, bytes memory eoaSig)`
    function validateUserOp(
        UserOperation calldata userOp, 
        bytes32 userOpHash, 
        uint256 /*missingAccountFunds*/
    ) external virtual returns (uint256 validationData) {
        (address signer, bytes memory nestedSig) = abi.decode(userOp.signature, (address, bytes));

        // terminate if recovered signer address does not match packed signer
        if (!SignatureChecker.isValidSignatureNow(signer, userOpHash, userOp.signature)) return SIG_VALIDATION_FAILED;

        // apply this validator's authentication logic
        bool validSigner = signer == Ownable(msg.sender).owner();
        validationData = validSigner ? 0 : SIG_VALIDATION_FAILED;
    }

    function isValidSignature(bytes32 userOpHash, bytes calldata signature) 
        external view virtual returns (bytes4 magicValue) 
    {
        // recover signer address, returning on malleable or invalid signatures
        (address signer, ECDSA.RecoverError err) = ECDSA.tryRecover(userOpHash, signature);
        // return if signature is malformed
        if (err != ECDSA.RecoverError.NoError) return INVALID_SIGNER;
        
        // apply this validator's authentication logic
        bool validSigner = signer == Ownable(msg.sender).owner();
        magicValue = validSigner ? this.isValidSignature.selector : INVALID_SIGNER;
    }
}