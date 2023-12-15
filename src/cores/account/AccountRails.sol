// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Rails} from "src/Rails.sol";
import {Account} from "src/cores/account/Account.sol";
import {IAccount} from "src/lib/ERC4337/interface/IAccount.sol";
import {IEntryPoint} from "src/lib/ERC4337/interface/IEntryPoint.sol";
import {UserOperation} from "src/lib/ERC4337/utils/UserOperation.sol";
import {Validators} from "src/validator/Validators.sol";
import {IValidator} from "src/validator/interface/IValidator.sol";
import {Operations} from "src/lib/Operations.sol";
import {Access} from "src/access/Access.sol";
import {SupportsInterface} from "src/lib/ERC165/SupportsInterface.sol";
import {ECDSA} from "openzeppelin-contracts/utils/cryptography/ECDSA.sol";
import {SignatureChecker} from "openzeppelin-contracts/utils/cryptography/SignatureChecker.sol";
import {IERC1271} from "openzeppelin-contracts/interfaces/IERC1271.sol";
import {ERC1155Receiver} from "openzeppelin-contracts/token/ERC1155/utils/ERC1155Receiver.sol";
import {IERC1155Receiver} from "openzeppelin-contracts/token/ERC1155/IERC1155Receiver.sol";

/// @title Station Network Account Abstract Contract
/// @author 👦🏻👦🏻.eth

/// @dev This abstract contract provides scaffolding for Station's Account signature validation
/// ERC1271 and ERC4337 compliance in combination with Rails's Permissions system
/// to provide convenient and modular private key management on an infrastructural level
abstract contract AccountRails is Account, Rails, Validators, IERC1271 {
    /*=============
        ACCOUNT
    ==============*/

    /// @dev Function enabling EIP-4337 compliance as a smart contract wallet account
    /// @param userOp The UserOperation to validate before executing
    /// @param userOpHash Hash of the UserOperation data, used as signature digest
    /// @param missingAccountFunds Delta representing this account's missing funds in the EntryPoint contract
    /// Corresponds to minimum native currency that must be transferred to the EntryPoint to complete execution
    /// Can be 0 if this account has already deposited enough funds or if a paymaster is used
    /// @notice To craft the signature, string concatenation or `abi.encodePacked` *must* be used
    /// Zero-padded data will fail. Ie: `abi.encodePacked(validatorData, signer, currentRSV)` is correct
    /**
     *   @return validationData A packed uint256 of three concatenated variables
     *   ie: `uint256(abi.encodePacked(address authorizor, uint48 validUntil, uint48 validAfter))`
     *   where `authorizer` can be one of the following:
     *       1. A signature aggregator contract, inheriting IAggregator.sol, to use for validation
     *       2. An exit status code `bytes20(0x01)` representing signature validation failure
     *       3. An empty `bytes20(0x0)` representing successful signature validation
     */
    function validateUserOp(UserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        public
        virtual
        returns (uint256 validationData)
    {
        // only EntryPoint should call this function to prevent frontrunning of valid signatures
        _checkSenderIsEntryPoint();

        bytes32 ethSignedUserOpHash = ECDSA.toEthSignedMessageHash(userOpHash);

        // try extracting packed validator data to check for modular validation format
        bytes8 flag = bytes8(userOp.signature[:8]);
        address validator = address(bytes20(userOp.signature[12:32]));

        if (flag == VALIDATOR_FLAG && isValidator(validator)) {
            bytes calldata formattedSig = userOp.signature[32:];

            // copy userOp into memory and format for Validator module
            UserOperation memory formattedUserOp = userOp;
            formattedUserOp.signature = formattedSig;

            uint256 ret =
                IValidator(validator).validateUserOp(formattedUserOp, ethSignedUserOpHash, missingAccountFunds);

            // if validator rejects sig, terminate early with status code 1
            if (ret != 0) return ret;
        } else {
            // support non-modular signatures by default
            address signer;
            bool validSig;
            // check if `v == 0` instead of the standard 27/28, in which case it is a contract signature
            if (userOp.signature[64] == 0) {
                (signer, validSig) = _isValidContractSignature(userOpHash, userOp.signature);
            } else {
                (signer, validSig) = _isValidECDSASignature(userOpHash, userOp.signature);
            }

            // to save gas, terminate early if a signature or authorization error was encountered
            if (!validSig || !_isAuthorizedSigner(signer)) {
                return 1;
            }
        }

        /// @notice BLS sig aggregator and timestamp expiry are not currently supported by this contract
        /// so `bytes20(0x0)` and `bytes6(0x0)` suffice. To enable support for aggregator and timestamp expiry,
        /// override the following params
        bytes20 authorizer;
        bytes6 validUntil;
        bytes6 validAfter;

        validationData = uint256(bytes32(abi.encodePacked(authorizer, validUntil, validAfter)));

        /// @notice nonce collision is managed entirely by the EntryPoint, but validation hook optionality
        /// for child contracts is provided here as `_checkNonce()` may be overridden
        _checkNonce();

        // check fee payment
        if (missingAccountFunds != 0) {
            _preFund(missingAccountFunds);
        }
    }

    /// @dev Function to recover a signer address from the provided hash and signature
    /// and then verify whether the recovered signer address is a recognized Turnkey
    /// @param hash The 32 byte digest derived by hashing signed message data. Sadly, name is canonical in ERC1271.
    /// @param signature The signature to be verified via recovery. May be prepended with validator flag and address
    /// @notice To craft the signature with prepend, string concatenation or `abi.encodePacked` *must* be used
    /// Zero-padded data will fail. Ie: `abi.encodePacked(validatorData, signer, currentRSV)` is correct
    /// @return magicValue The 4-byte value representing signature validity, as defined by EIP1271
    /// Can be one of three values:
    ///   - `this.isValidSignature.selector` indicates a valid signature
    ///   - `bytes4(hex'ffffffff')` indicates a signature failure bubbled up from an external modular validator
    ///   - `bytes4(0)` indicates a default signature failure, ie not using the modular `VALIDATOR_FLAG`
    function isValidSignature(bytes32 hash, bytes calldata signature) public view returns (bytes4 magicValue) {
        // try extracting packed validator data to check for modular validation format
        bytes8 flag = bytes8(signature[:8]);
        address validator = address(bytes20(signature[12:32]));

        // collision of a signature's first 8 bytes with flag is very unlikely; impossible when incl validator address
        if (flag == VALIDATOR_FLAG && isValidator(validator)) {
            bytes calldata formattedSig = signature[0x20:];
            bytes4 ret = IValidator(validator).isValidSignature(hash, formattedSig);

            // validator will return either correct `magicValue` or error code `INVALID_SIGNER`
            magicValue = ret;
        } else {
            // support non-modular signatures by default
            address signer;
            bool validSig;
            // check if `v == 0` instead of the standard 27/28, in which case it is a contract signature
            if (signature[64] == 0) {
                (signer, validSig) = _isValidContractSignature(hash, signature);
            } else {
                (signer, validSig) = _isValidECDSASignature(hash, signature);
            }

            if (validSig && _isAuthorizedSigner(signer)) {
                magicValue = this.isValidSignature.selector;
            }
        }
    }

    /*===============
        INTERNALS
    ===============*/

    function _isAuthorizedSigner(address _signer) internal view virtual returns (bool);

    /// @dev Recover and authenticate a signer address in the context of `isValidSignature()`,
    /// called only on signatures that were not constructed using the modular verification flag
    /// @notice Accounts do not express opinion on whether the `signer` is encoded into `userOp.signature`,
    /// so the OZ ECDSA library should be used rather than the SignatureChecker
    function _isValidECDSASignature(bytes32 _hash, bytes memory _signature) internal view virtual returns (address _signer, bool _valid) {
        // support non-modular signatures by recovering signer address and reverting malleable or invalid signatures
        ECDSA.RecoverError err;
        (_signer, err) = ECDSA.tryRecover(_hash, _signature);
        
        // return if signature is malformed
        if (err == ECDSA.RecoverError.NoError) {
            _valid = true;
        }
    }

    /// @dev Smart contract signatures must provide a `v` value of 0 and abi encode the contract signer address into `r`
    /// as well as provide an `s` value which is the current context's calldata offset where the originator's signature is located
    /// In short, contract signatures follow this format: `abi.encodePacked(bytes32(signerAddress), uint256(sigOffset), uint8(0), bytes(sig))`
    function _isValidContractSignature(bytes32 _hash, bytes calldata _signature) internal view virtual returns (address _signer, bool _valid) {
        // for contract signatures, `_signer` refers to the contract whose address is encoded into `r` rather than signature originator
        _signer = address(bytes20(_signature[12:32]));

        uint256 offset = uint256(bytes32(_signature[32:64]));
        bytes calldata _sig = _signature[offset:];
        _valid = SignatureChecker.isValidERC1271SignatureNow(_signer, _hash, _sig);
    }

    /// @dev View function to limit callers to only the EntryPoint contract of this chain
    function _checkSenderIsEntryPoint() internal virtual {
        if (msg.sender != entryPoint) revert NotEntryPoint(msg.sender);
    }

    /// @dev Since nonce management and collision checks are handled entirely by the EntryPoint,
    /// this function is left empty for contracts inheriting from this one to use EntryPoint's defaults
    /// If sequential `UserOperation` nonce ordering is desired, override this, eg: `require(nonce < type(uint64).max)`
    function _checkNonce() internal view virtual {}

    /// @dev Function to pre-fund the EntryPoint contract with delta of native currency funds required for a UserOperation
    /// By default, this function only sends enough funds to complete the current context's UserOperation
    /// Override if sending custom amounts > `_missingAccountFunds` (or < if reverts are preferrable)
    function _preFund(uint256 _missingAccountFunds) internal virtual {
        (bool r,) = payable(msg.sender).call{value: _missingAccountFunds}("");
        require(r);
    }

    /*===============
        OVERRIDES
    ===============*/

    /// @dev Declare explicit ERC165 support for ERC1271 interface in addition to existing interfaces
    /// @param interfaceId The interfaceId to check for support
    /// @return _ Boolean indicating whether the contract supports the specified interface.
    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(Rails, Validators, ERC1155Receiver)
        returns (bool)
    {
        return (
            interfaceId == type(IERC1271).interfaceId || interfaceId == type(IAccount).interfaceId
                || interfaceId == type(IERC1155Receiver).interfaceId || Rails.supportsInterface(interfaceId)
                || Validators.supportsInterface(interfaceId)
        );
    }

    /// @dev Provides control over adding and removing recognized validator contracts
    /// only to either the owner or entities possessing `ADMIN` or `VALIDATOR` permissions
    /// @notice Can be overridden for more restrictive access if desired
    function _checkCanUpdateValidators() internal virtual override {
        _checkPermission(Operations.VALIDATOR, _msgSender());
    }

    /// @dev Provides control over Turnkey addresses to the owner only
    /// @notice Permission to `addPermission(Operations.CALL_PERMIT)`, which is the intended
    /// function call to be called by the owner for adding valid signer accounts such as Turnkeys,
    /// is restricted to only the owner
    function _checkCanUpdatePermissions() internal virtual override {
        _checkPermission(Operations.PERMISSIONS, _msgSender());
    }

    function _checkCanUpdateGuards() internal virtual override {
        _checkPermission(Operations.GUARDS, _msgSender());
    }

    /// @dev Permission to `Call::call()` via signature validation is restricted to either
    /// the EntryPoint, the owner, or entities possessing the `CALL`or `ADMIN` permissions
    /// @notice Mutiny by Turnkeys is prevented by granting them only the `CALL_PERMIT` permission
    function _checkCanExecuteCall() internal view virtual override {
        bool auth = (msg.sender == entryPoint || hasPermission(Operations.CALL, _msgSender()));
        if (!auth) revert PermissionDoesNotExist(Operations.CALL, _msgSender());
    }

    /// @dev Provides control over ERC165 layout to addresses with `INTERFACE` permission
    function _checkCanUpdateInterfaces() internal virtual override {
        _checkPermission(Operations.INTERFACE, _msgSender());
    }
}
