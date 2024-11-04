// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {ProofOfReceivedEmailFromDhruv} from "../src/ProofOfReceivedEmailFromDhruv.sol";
import { Verifier } from "../src/verifier.sol";
import "@zk-email/contracts/DKIMRegistry.sol";
import "../src/utils/StringUtils.sol";

contract TestProofOfReceivedEmailFromDhruv is Test {
    using StringUtils for *;

    Verifier proofVerifier;
    DKIMRegistry dkimRegistry;
    ProofOfReceivedEmailFromDhruv testVerifier;

    uint16 public constant packSize = 7;
    address constant VM_ADDR = 0x7109709ECfa91a80626fF3989D68f67F5b1DD12D; // Hardcoded address of the VM from foundry

    function setUp() public {
        address owner = vm.addr(1);

        vm.startPrank(owner);

        proofVerifier = new Verifier();
        dkimRegistry = new DKIMRegistry(owner);

        // These are the Poseidon hash of DKIM public keys for x.com
        // This was calcualted using https://github.com/zkemail/zk-email-verify/tree/main/packages/scripts
        dkimRegistry.setDKIMPublicKeyHash(
            "gmail.com",
            0x0ea9c777dc7110e5a9e89b13f0cfc540e3845ba120b2b6dc24024d61488d4788
        );

        testVerifier = new ProofOfReceivedEmailFromDhruv(proofVerifier, dkimRegistry);

        vm.stopPrank();
    }

    // Should pass (note that there are extra 0 bytes, which are filtered out but should be noted in audits)
    function testUnpack1() public {
        uint256[] memory packedBytes = new uint256[](3);
        packedBytes[0] = 29096824819513600;
        packedBytes[1] = 0;
        packedBytes[2] = 0;

        // This is 0x797573685f670000000000000000000000000000000000000000000000000000
        // packSize = 7
        string memory byteList = StringUtils.convertPackedBytesToString(
            packedBytes,
            15,
            packSize
        );
        // This is 0x797573685f67, since strings are internally arbitrary length arrays
        string memory intended_value = "yush_g";

        // We need to cast both to bytes32, which works since usernames can be at most 15, alphanumeric + '_' characters
        // Note that this may not generalize to non-ascii characters.
        // Weird characters are allowed in email addresses, see https://en.wikipedia.org/wiki/Email_address#Local-part
        // See https://stackoverflow.com/a/2049510/3977093 -- you can even have international characters with RFC 6532
        // Our regex should just disallow most of these emails, but they may end up taking more than two bytes
        // ASCII should fit in 2 bytes but emails may not be ASCII
        assertEq(bytes32(bytes(byteList)), bytes32(bytes(intended_value)));
        assertEq(byteList, intended_value);
        console.logString(byteList);
    }

    function testUnpack2() public {
        uint256[] memory packedBytes = new uint256[](3);
        packedBytes[0] = 28557011619965818;
        packedBytes[1] = 1818845549;
        packedBytes[2] = 0;
        string memory byteList = StringUtils.convertPackedBytesToString(
            packedBytes,
            15,
            packSize
        );
        string memory intended_value = "zktestemail";
        assertEq(bytes32(bytes(byteList)), bytes32(bytes(intended_value)));
        console.logString(byteList);
    }

    // These proof and public input values are generated using scripts in packages/circuits/scripts/generate-proof.ts
    // The sample email in `/emls` is used as the input, but you will have different values if you generated your own zkeys
//["0x0ea9c777dc7110e5a9e89b13f0cfc540e3845ba120b2b6dc24024d61488d4788","0x00000000000000007564652e616c63752e674032316b65657261707675726864","0x00000000000000006d6f632e6c69616d67403338386b65657261707675726864","0x0000000000000000000000001234567890123456789012345678901234567890"]
    function testVerifyTestEmail() public {
        uint256[4] memory publicSignals;
        publicSignals[0] = 0x0ea9c777dc7110e5a9e89b13f0cfc540e3845ba120b2b6dc24024d61488d4788;
        publicSignals[1] = 0x00000000000000007564652e616c63752e674032316b65657261707675726864;
        publicSignals[2] = 0x00000000000000006d6f632e6c69616d67403338386b65657261707675726864;
        publicSignals[3] = 0x0000000000000000000000001234567890123456789012345678901234567890;

//["0x2ce0e2b2f21010baded4ab40f9c0e8b4bf0c32e478f387fe2f27e69ceafd44f7", "0x2ea13957b52c7d8258109591ee3d06254fe2a2d7c69017575958af43ae6c627b"]
        uint256[2] memory proof_a = [
            0x2ce0e2b2f21010baded4ab40f9c0e8b4bf0c32e478f387fe2f27e69ceafd44f7,
            0x2ea13957b52c7d8258109591ee3d06254fe2a2d7c69017575958af43ae6c627b
        ];

//[["0x1815a15fbfd7285df22af9b723e2a10a810bd61e07a95d3ebdecec82225d85b3", "0x07766f97dc2e4881af4909fe55023744bbfdb4bb60deeb891dc7f18c356d3315"],["0x1ce7cb7c7861d825aeacb46a0ad25e6b961ab1a96b74f6a34be6d7d6e3958164", "0x237c0aa1e25f83c557c35b1dc6b29602ae98be4798af5fc1cb804c5658da201a"]]
        // Note: you need to swap the order of the two elements in each subarray
        uint256[2][2] memory proof_b = [
            [
                0x1815a15fbfd7285df22af9b723e2a10a810bd61e07a95d3ebdecec82225d85b3,
                0x07766f97dc2e4881af4909fe55023744bbfdb4bb60deeb891dc7f18c356d3315
            ],
            [
                0x1ce7cb7c7861d825aeacb46a0ad25e6b961ab1a96b74f6a34be6d7d6e3958164,
                0x237c0aa1e25f83c557c35b1dc6b29602ae98be4798af5fc1cb804c5658da201a
            ]
        ];
//["0x08b20a8179fae3a2e11263b4a721fa88f892871377fb86eb2c943bf8d15838aa", "0x00dcd29f9e8141f0aa7178e9cf129771ac2f574ed3d21e36737f45f5d340b506"]
        uint256[2] memory proof_c = [
            0x08b20a8179fae3a2e11263b4a721fa88f892871377fb86eb2c943bf8d15838aa,
            0x00dcd29f9e8141f0aa7178e9cf129771ac2f574ed3d21e36737f45f5d340b506
        ];

        uint256[8] memory proof = [
            proof_a[0],
            proof_a[1],
            proof_b[0][0],
            proof_b[0][1],
            proof_b[1][0],
            proof_b[1][1],
            proof_c[0],
            proof_c[1]
        ];

        // Test proof verification
        bool verified = proofVerifier.verifyProof(
            proof_a,
            proof_b,
            proof_c,
            publicSignals
        );
        assertEq(verified, true);

        // Test mint after spoofing msg.sender
        vm.startPrank(0x1234567890123456789012345678901234567890);
        assertEq(testVerifier.mint(proof, publicSignals), true);
        vm.stopPrank();

        // Test mint after spoofing msg.sender
        vm.startPrank(0x1234567890123456789012345678901234567890);
        assertEq(testVerifier.mint(proof, publicSignals), false);
        vm.stopPrank();
    }
}