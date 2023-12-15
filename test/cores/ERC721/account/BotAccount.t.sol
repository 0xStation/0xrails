// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import "forge-std/console2.sol";
import {CallPermitValidator} from "src/validator/CallPermitValidator.sol";
import {BotAccount} from "src/cores/account/BotAccount.sol";
import {BotAccountFactory} from "src/cores/account/factory/BotAccountFactory.sol";
import {IAccountFactory} from "src/cores/account/factory/interface/IAccountFactory.sol";
import {Operations} from "src/lib/Operations.sol";
import {UserOperation} from "src/lib/ERC4337/utils/UserOperation.sol";
import {IERC1271} from "openzeppelin-contracts/interfaces/IERC1271.sol";
import {ECDSA} from "openzeppelin-contracts/utils/cryptography/ECDSA.sol";
import {IOwnable} from "src/access/ownable/interface/IOwnable.sol";
import {IPermissions} from "src/access/permissions/interface/IPermissions.sol";
import {IGuards} from "src/guard/interface/IGuards.sol";
import {IExtensions} from "src/extension/interface/IExtensions.sol";
import {ERC1967Proxy} from "openzeppelin-contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract BotAccountTest is Test {
    BotAccount public botAccountImpl;
    BotAccount public botAccount;
    CallPermitValidator public callPermitValidator;
    BotAccountFactory public botAccountFactoryImpl;
    BotAccountFactory public botAccountFactoryProxy;

    address public entryPointAddress;
    address public owner;
    address public testTurnkey;
    address[] turnkeyArray;

    UserOperation public userOp;
    bytes32 public userOpHash;
    bytes32 public ethSignedUserOpHash;
    bytes32 public salt;
    bytes public botAccountFactoryInitData;

    // intended to contain custom error signatures
    bytes public err;

    function setUp() public {
        // use actual EntryPoint deployment address
        entryPointAddress = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;
        owner = vm.addr(0xbeefEEbabe);
        testTurnkey = vm.addr(0xc0ffEEbabe);
        turnkeyArray.push(testTurnkey);

        callPermitValidator = new CallPermitValidator(entryPointAddress);

        userOp = UserOperation({
            sender: testTurnkey,
            nonce: 0,
            initCode: "",
            callData: "",
            callGasLimit: 0,
            verificationGasLimit: 0,
            preVerificationGas: 0,
            maxFeePerGas: 0,
            maxPriorityFeePerGas: 0,
            paymasterAndData: "",
            signature: ""
        });
        userOpHash = callPermitValidator.getUserOpHash(userOp);
        ethSignedUserOpHash = ECDSA.toEthSignedMessageHash(userOpHash);
        salt = bytes32("garlicsalt");

        botAccountImpl = new BotAccount(entryPointAddress);
        botAccountFactoryImpl = new BotAccountFactory();
        botAccountFactoryInitData =
            abi.encodeWithSelector(BotAccountFactory.initialize.selector, address(botAccountImpl), owner);
        botAccountFactoryProxy =
            BotAccountFactory(address(new ERC1967Proxy(address(botAccountFactoryImpl), botAccountFactoryInitData)));
        botAccount = BotAccount(
            payable(botAccountFactoryProxy.createBotAccount(salt, owner, address(callPermitValidator), turnkeyArray))
        );
    }

    function test_setUp() public {
        assertEq(botAccount.entryPoint(), entryPointAddress);
        assertEq(botAccount.owner(), owner);
        assertEq(botAccountFactoryProxy.getAccountImpl(), address(botAccountImpl));

        assertTrue(botAccount.supportsInterface(type(IERC1271).interfaceId));
        assertTrue(botAccount.supportsInterface(botAccount.erc165Id()));
        assertTrue(botAccount.supportsInterface(type(IPermissions).interfaceId));
        assertTrue(botAccount.supportsInterface(type(IGuards).interfaceId));
        assertTrue(botAccount.supportsInterface(type(IExtensions).interfaceId));

        assertTrue(botAccount.hasPermission(Operations.CALL_PERMIT, testTurnkey));
    }

    function test_isValidSignature(uint256 startingPrivateKey, uint8 numPrivateKeys) public {
        address[] memory newTurnkeys = new address[](numPrivateKeys);

        address currentAddr;
        bytes[] memory formattedSignatures = new bytes[](numPrivateKeys);
        for (uint8 i; i < numPrivateKeys; ++i) {
            // private keys must be nonzero and less than the secp256k curve order
            vm.assume(startingPrivateKey != 0);
            vm.assume(startingPrivateKey < 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_BAAEDCE6_AF48A03B_BFD25E8C_D0364141);

            uint256 currentPrivateKey = startingPrivateKey + i;
            currentAddr = vm.addr(currentPrivateKey);
            newTurnkeys[i] = currentAddr;

            vm.prank(owner);
            botAccount.addPermission(Operations.CALL_PERMIT, currentAddr);

            (uint8 v, bytes32 r, bytes32 s) = vm.sign(currentPrivateKey, userOpHash);
            bytes memory currentRSV = abi.encodePacked(r, s, v);
            assertEq(currentRSV.length, 65);

            // ModularValidation schema developed by GroupOS requires prepended `validatorFlag` packed with validator address
            // pack 32-byte word using `validatorFlag` OR against `address`
            bytes32 validatorData =
                botAccount.VALIDATOR_FLAG() | bytes32(uint256(uint160(address(callPermitValidator))));
            // using `abi.encodePacked()`, pack `validatorData` and `signer` address with signature
            bytes memory formattedSig = abi.encodePacked(validatorData, currentAddr, currentRSV);

            formattedSignatures[i] = formattedSig;
        }

        for (uint8 j; j < numPrivateKeys; ++j) {
            bytes4 eip1271ActualVal = 0x1626ba7e;
            bytes4 eip1271RetVal = botAccount.isValidSignature(userOpHash, formattedSignatures[j]);
            assertEq(eip1271RetVal, eip1271ActualVal);
        }
    }

    function test_validateUserOp(uint256 startingPrivateKey, uint8 numPrivateKeys) public {
        address currentAddr;
        for (uint8 i; i < numPrivateKeys; ++i) {
            // private keys must be nonzero and less than the secp256k curve order
            vm.assume(startingPrivateKey != 0);
            vm.assume(startingPrivateKey < 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_BAAEDCE6_AF48A03B_BFD25E8C_D0364141);

            uint256 currentPrivateKey = startingPrivateKey + i;
            currentAddr = vm.addr(currentPrivateKey);

            vm.prank(owner);
            botAccount.addPermission(Operations.CALL_PERMIT, currentAddr);

            // populate preexisting UserOperation `userOp` with formatted signature to be validated
            UserOperation memory currentUserOp = userOp;
            bytes32 currentUserOpHash = callPermitValidator.getUserOpHash(currentUserOp);
            bytes32 ethSignedCurrentUserOpHash = ECDSA.toEthSignedMessageHash(currentUserOpHash);

            (uint8 v, bytes32 r, bytes32 s) = vm.sign(currentPrivateKey, ethSignedCurrentUserOpHash);
            bytes memory currentRSV = abi.encodePacked(r, s, v);
            assertEq(currentRSV.length, 65);

            // ModularValidation schema developed by GroupOS requires prepended validatorFlag & validator address
            // pack 32-byte word using `VALIDATOR_FLAG` OR against `address`
            bytes32 validatorData =
                botAccount.VALIDATOR_FLAG() | bytes32(uint256(uint160(address(callPermitValidator))));
            // using `abi.encodePacked()`, pack `validatorData` and `signer` address with signature
            bytes memory formattedSig = abi.encodePacked(validatorData, currentAddr, currentRSV);
            currentUserOp.signature = formattedSig;

            uint256 expectedValidationData = 0;
            uint256 missingAccountFunds = 0;
            vm.prank(entryPointAddress);
            uint256 returnedValidationData = botAccount.validateUserOp(currentUserOp, userOpHash, missingAccountFunds);
            assertEq(returnedValidationData, expectedValidationData);
        }
    }

    function test_addTurnkey(uint256 startingPrivateKey, uint8 numPrivateKeys) public {
        address[] memory newTurnkeys = new address[](numPrivateKeys);
        bytes8 op = Operations.CALL_PERMIT;

        address currentAddr;
        for (uint8 i; i < numPrivateKeys; ++i) {
            // private keys must be nonzero and less than the secp256k curve order
            vm.assume(startingPrivateKey != 0);
            vm.assume(
                startingPrivateKey
                    < 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_BAAEDCE6_AF48A03B_BFD25E8C_D0364141 - numPrivateKeys
            );

            currentAddr = vm.addr(startingPrivateKey + i);
            newTurnkeys[i] = currentAddr;
            vm.prank(owner);
            botAccount.addPermission(op, currentAddr);
        }

        for (uint256 j; j < newTurnkeys.length; ++j) {
            currentAddr = newTurnkeys[j];
            assertTrue(botAccount.hasPermission(op, currentAddr));
        }

        // extra permission is due to testTurnkey added in setUp()
        assertEq(botAccount.getAllPermissions().length, uint256(numPrivateKeys) + 1);
    }

    function test_addTurnkeyRevertPermissionDoesNotExist(address someAddress) public {
        err =
            abi.encodeWithSelector(IPermissions.PermissionDoesNotExist.selector, Operations.PERMISSIONS, address(this));
        vm.expectRevert(err);
        botAccount.addPermission(Operations.CALL_PERMIT, someAddress);
    }

    function test_removeTurnkey(uint256 startingPrivateKey, uint8 numPrivateKeys) public {
        address[] memory newTurnkeys = new address[](numPrivateKeys);
        bytes8 op = Operations.CALL_PERMIT;

        address currentAddr;
        for (uint8 i; i < numPrivateKeys; ++i) {
            // private keys must be nonzero and less than the secp256k curve order
            vm.assume(startingPrivateKey != 0);
            vm.assume(
                startingPrivateKey
                    < 0xFFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFE_BAAEDCE6_AF48A03B_BFD25E8C_D0364141 - numPrivateKeys
            );

            currentAddr = vm.addr(startingPrivateKey + i);
            newTurnkeys[i] = currentAddr;
            vm.prank(owner);
            botAccount.addPermission(op, currentAddr);
        }

        for (uint256 j; j < newTurnkeys.length; ++j) {
            currentAddr = newTurnkeys[j];
            assertTrue(botAccount.hasPermission(op, currentAddr));

            vm.prank(owner);
            botAccount.removePermission(op, currentAddr);

            assertFalse(botAccount.hasPermission(op, currentAddr));
        }

        // extra permission is due to testTurnkey added in setUp()
        assertEq(botAccount.getAllPermissions().length, 1);

        vm.prank(owner);
        botAccount.removePermission(op, testTurnkey);
        assertEq(botAccount.getAllPermissions().length, 0);
    }

    function test_removeTurnkeyRevertPermissionDoesNotExist(address someAddress) public {
        bytes8 op = Operations.CALL_PERMIT;
        vm.prank(owner);
        botAccount.addPermission(op, someAddress);

        // attempt removal of added permission without pranking owner
        err =
            abi.encodeWithSelector(IPermissions.PermissionDoesNotExist.selector, Operations.PERMISSIONS, address(this));
        vm.expectRevert(err);
        botAccount.removePermission(op, someAddress);
    }

    function test_validatorFlag1271() public {
        uint256 turnkeyPrivatekey = 0xc0ffEEbabe;
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(turnkeyPrivatekey, userOpHash);
        bytes memory sig = abi.encodePacked(r, s, v);
        bytes8 validatorFlag = botAccount.VALIDATOR_FLAG(); // 0xf88284b100000000

        // pack 32-byte word using `validatorFlag` OR against `address`
        bytes32 validatorData = validatorFlag | bytes32(uint256(uint160(address(callPermitValidator))));
        // using `abi.encodePacked()`, pack `validatorData` and `signer` address with signature
        bytes memory formattedSig = abi.encodePacked(validatorData, testTurnkey, sig);

        // `formattedSig` comprises following calldata, concatenated:
        // bytes32(0xf88284b100000000000000005615deb798bb3e4dfa0139dfa1b3d433cc23b72f)
        // address(0xacbbb44523ee8581536434b182f775878d2889ac)
        // bytes65(0836d9f518d3f3261d7838324bf6c9c5916ae6eb7ee5c9b34c899e8286bac2537b4283b2912f406aa54e7d744276ebdc6d3d8c6969c6f7c0ef134c0c877f1c8f1b)
        bytes4 retVal = botAccount.isValidSignature(userOpHash, formattedSig);
        bytes4 expectedVal = botAccount.isValidSignature.selector;
        assertEq(retVal, expectedVal);
    }

    function test_validatorFlag4337() public {
        uint256 turnkeyPrivatekey = 0xc0ffEEbabe;
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(turnkeyPrivatekey, ethSignedUserOpHash);
        bytes memory sig = abi.encodePacked(r, s, v);
        bytes8 validatorFlag = botAccount.VALIDATOR_FLAG(); // 0xf88284b100000000

        // pack 32-byte word using `validatorFlag` OR against `address`
        bytes32 validatorData = validatorFlag | bytes32(uint256(uint160(address(callPermitValidator))));
        // using `abi.encodePacked()`, pack `validatorData` and `signer` address with signature
        bytes memory formattedSig = abi.encodePacked(validatorData, testTurnkey, sig);

        userOp.signature = formattedSig;
        vm.prank(entryPointAddress);
        uint256 retUint = botAccount.validateUserOp(userOp, userOpHash, 0);
        assertEq(retUint, 0);
    }

    function test_invalidValidatorFlag1271() public {
        uint256 turnkeyPrivatekey = 0xc0ffEEbabe;
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(turnkeyPrivatekey, userOpHash);
        bytes memory sig = abi.encodePacked(r, s, v);
        bytes8 wrongValidatorFlag = bytes8(uint64(botAccount.VALIDATOR_FLAG()) + 1); // 0xf88284b100000001

        // pack 32-byte word using `wrongValidatorFlag` OR against `address`
        bytes32 validatorData = wrongValidatorFlag | bytes32(uint256(uint160(address(callPermitValidator))));
        // using `abi.encodePacked()`, pack `validatorData` and `signer` address with signature
        bytes memory formattedSig = abi.encodePacked(validatorData, sig);

        bytes4 retVal = botAccount.isValidSignature(userOpHash, formattedSig);
        bytes4 expectedVal = 0; // expect EIP1271 sig error: bytes4(0)
        assertEq(retVal, expectedVal);
    }

    function test_invalidValidatorFlag4337() public {
        uint256 turnkeyPrivatekey = 0xc0ffEEbabe;
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(turnkeyPrivatekey, ethSignedUserOpHash);
        bytes memory sig = abi.encodePacked(r, s, v);
        bytes8 wrongValidatorFlag = bytes8(uint64(botAccount.VALIDATOR_FLAG()) + 1); // 0xf88284b100000001

        // pack 32-byte word using `wrongValidatorFlag` OR against `address`
        bytes32 validatorData = wrongValidatorFlag | bytes32(uint256(uint160(address(callPermitValidator))));
        // using `abi.encodePacked()`, pack `validatorData` and `signer` address with signature
        bytes memory formattedSig = abi.encodePacked(validatorData, sig);

        userOp.signature = formattedSig;
        vm.prank(entryPointAddress);
        uint256 retUint = botAccount.validateUserOp(userOp, userOpHash, 0);
        assertEq(retUint, 1); // expect EIP4337 sig error: 1
    }

    function test_defaultSignature1271() public {
        uint256 ownerPrivatekey = 0xbeefEEbabe;
        UserOperation memory newUserOp = userOp;

        bytes32 newUserOpHash = callPermitValidator.getUserOpHash(newUserOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivatekey, newUserOpHash);
        bytes memory sig = abi.encodePacked(r, s, v);

        bytes4 retVal = botAccount.isValidSignature(newUserOpHash, sig);
        bytes4 expectedVal = botAccount.isValidSignature.selector;
        assertEq(retVal, expectedVal);
    }

    function test_defaultSignature4337() public {
        uint256 ownerPrivatekey = 0xbeefEEbabe;
        UserOperation memory newUserOp = userOp;

        bytes32 newUserOpHash = callPermitValidator.getUserOpHash(newUserOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPrivatekey, newUserOpHash);
        bytes memory sig = abi.encodePacked(r, s, v);

        newUserOp.signature = sig;
        vm.prank(entryPointAddress);
        uint256 retUint = botAccount.validateUserOp(newUserOp, newUserOpHash, 0);
        assertEq(retUint, 0); // expect 4337 success code: 0
    }

    function test_invalidDefaultSignature1271() public {
        uint256 notOwnerPrivatekey = 0xdead;
        UserOperation memory newUserOp = userOp;

        bytes32 newUserOpHash = callPermitValidator.getUserOpHash(newUserOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(notOwnerPrivatekey, newUserOpHash);
        bytes memory sig = abi.encodePacked(r, s, v);

        bytes4 retVal = botAccount.isValidSignature(newUserOpHash, sig);
        bytes4 expectedVal = bytes4(0); // expect default signature error code: bytes4(0)
        assertEq(retVal, expectedVal);
    }

    function test_invalidDefaultSignature4337() public {
        uint256 notOwnerPrivatekey = 0xdead;
        UserOperation memory newUserOp = userOp;

        bytes32 newUserOpHash = callPermitValidator.getUserOpHash(newUserOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(notOwnerPrivatekey, ECDSA.toEthSignedMessageHash(newUserOpHash));
        bytes memory sig = abi.encodePacked(r, s, v);

        newUserOp.signature = sig;
        vm.prank(entryPointAddress);
        uint256 retUint = botAccount.validateUserOp(newUserOp, newUserOpHash, 0);
        assertEq(retUint, 1); // expect 4337 failure code: 1
    }

    function test_isValidSignatureFromSmartContract() public {
        bytes32 contractSignerSalt = bytes32(uint256(salt) + 1);
        uint256 contractSignerOwnerPrivKey = 0xc0ffee;
        address contractSignerOwner = vm.addr(contractSignerOwnerPrivKey);
        BotAccount contractSigner = BotAccount(payable(botAccountFactoryProxy.createBotAccount(contractSignerSalt, contractSignerOwner, address(callPermitValidator), turnkeyArray)));

        assertEq(contractSigner.owner(), contractSignerOwner);
        assertTrue(contractSigner.hasPermission(Operations.CALL_PERMIT, testTurnkey));
        
        // smart contract signature params- v == 0 is used as a flag for contract signatures
        bytes32 contractSignatureR = bytes32(abi.encode(address(contractSigner))); // encoded signer address (smart contract, not originator)
        uint256 contractSignatureS = 65; // offset of EOA originator's signature, permissioned on contractSigner via ERC1271
        uint8 contractSignatureV = 0;

        // sign an example message, ie userOp
        UserOperation memory newUserOp = userOp;
        bytes32 newUserOpHash = callPermitValidator.getUserOpHash(newUserOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(contractSignerOwnerPrivKey, newUserOpHash);
        bytes memory originatorSignature = abi.encodePacked(r, s, v);

        bytes memory contractSignature = abi.encodePacked(contractSignatureR, contractSignatureS, contractSignatureV, originatorSignature);
        
        // add permission to smart contract signer
        vm.prank(owner);
        botAccount.addPermission(Operations.CALL_PERMIT, address(contractSigner));

        bytes4 retVal = botAccount.isValidSignature(newUserOpHash, contractSignature);
        bytes4 expectedVal = botAccount.isValidSignature.selector;
        assertEq(retVal, expectedVal);
    }

    function test_validateUserOpSignatureFromSmartContract() public {
        bytes32 contractSignerSalt = bytes32(uint256(salt) + 1);
        uint256 contractSignerOwnerPrivKey = 0xc0ffee;
        address contractSignerOwner = vm.addr(contractSignerOwnerPrivKey);
        BotAccount contractSigner = BotAccount(payable(botAccountFactoryProxy.createBotAccount(contractSignerSalt, contractSignerOwner, address(callPermitValidator), turnkeyArray)));

        assertEq(contractSigner.owner(), contractSignerOwner);
        assertTrue(contractSigner.hasPermission(Operations.CALL_PERMIT, testTurnkey));
        
        // smart contract signature params- v == 0 is used as a flag for contract signatures
        bytes32 contractSignatureR = bytes32(abi.encode(address(contractSigner))); // encoded signer address (smart contract, not originator)
        uint256 contractSignatureS = 65; // offset of EOA originator's signature, permissioned on contractSigner via ERC1271
        uint8 contractSignatureV = 0;

        // sign an example userOp
        UserOperation memory newUserOp = userOp;
        bytes32 newUserOpHash = callPermitValidator.getUserOpHash(newUserOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(contractSignerOwnerPrivKey, newUserOpHash);
        bytes memory originatorSignature = abi.encodePacked(r, s, v);

        bytes memory contractSignature = abi.encodePacked(contractSignatureR, contractSignatureS, contractSignatureV, originatorSignature);
        newUserOp.signature = contractSignature;
        
        // add permission to smart contract signer
        vm.prank(owner);
        botAccount.addPermission(Operations.CALL_PERMIT, address(contractSigner));

        vm.prank(entryPointAddress);
        uint256 retUint = botAccount.validateUserOp(newUserOp, newUserOpHash, 0);
        assertEq(retUint, 0); // expect 4337 success code 0
    }
}
