import { ethers } from 'ethers'

import Encryptor from '../src/enc/encryptor'
import SignerP1 from '../src/sign/signer-p1'
import SignerP2 from '../src/sign/signer-p2'
import {TPCEcdsaSign} from "@safeheron/two-party-ecdsa-js";
import BN from "bn.js";
import {verifySig} from "../src/sign/verify";
import assert from "assert";

const keyshare1 = '' +
    '{\n' +
    '        "x1": "94373c9217b7d66356dcada81511b942874d002c6fed862207b01c336dd8484b",\n' +
    '        "Q": {\n' +
    '            "curve": "secp256k1",\n' +
    '            "x": "7f973242ba5f6983bafe605e2dcc1243dac3dbc88a852033ecc54a9081aa651f",\n' +
    '            "y": "820645834484f758e4ae9e2f3738fb8d230be91db55d0f7f86e72bbbe5147bc8"\n' +
    '        },\n' +
    '        "pailPubKey": {\n' +
    '            "n": "a596aafa6c9ecde4e4a360136816b89f8fbc43460055cef1318275ac1d6914cf73d731d6320337f3ae8ab99344ee1defe12b6a368df99774e3ee2e6efd174ea2a323f7881d1580b460a0530cc7c9006f97fa8c5890f7d66f96c499f9dc3f8729f70b9a2540e7bf98480e1c735121eaa4bfe484819cbfdff06859d24e2a332ab8ba1083dfc315437649857976c2c1c28dc86e930004e67af106e82ce94b6321b1de4abff30d68dd4174960b98d7f8cee09bc68abf3eeb93c9287031af6305020f691c67d64316d5fbb4929dc7227a3676dcf7f0589eab661b1a5a625b0fc44f1939326b952a44e9d990435f08c4d7d11cffd79303822e70dfbeacd8fec1b65fa1",\n' +
    '            "g": "a596aafa6c9ecde4e4a360136816b89f8fbc43460055cef1318275ac1d6914cf73d731d6320337f3ae8ab99344ee1defe12b6a368df99774e3ee2e6efd174ea2a323f7881d1580b460a0530cc7c9006f97fa8c5890f7d66f96c499f9dc3f8729f70b9a2540e7bf98480e1c735121eaa4bfe484819cbfdff06859d24e2a332ab8ba1083dfc315437649857976c2c1c28dc86e930004e67af106e82ce94b6321b1de4abff30d68dd4174960b98d7f8cee09bc68abf3eeb93c9287031af6305020f691c67d64316d5fbb4929dc7227a3676dcf7f0589eab661b1a5a625b0fc44f1939326b952a44e9d990435f08c4d7d11cffd79303822e70dfbeacd8fec1b65fa2"\n' +
    '        },\n' +
    '        "pailPrivKey": {\n' +
    '            "lambda": "a596aafa6c9ecde4e4a360136816b89f8fbc43460055cef1318275ac1d6914cf73d731d6320337f3ae8ab99344ee1defe12b6a368df99774e3ee2e6efd174ea2a323f7881d1580b460a0530cc7c9006f97fa8c5890f7d66f96c499f9dc3f8729f70b9a2540e7bf98480e1c735121eaa4bfe484819cbfdff06859d24e2a332ab71e0bbd7b2a3cca7c3d0506ad6b22e04029f6c03b1c94265b1c189ce84e30b0e803dad3b9c5c219a9b95d1e9cd437fa0f63b2cbba5196205211bd763adeb2fd0c8be537102bbcbb8bf496370dd2ff07085491d6bde43ddd4a91ecf9bd3a226a4a6cc95151cc5537b6d939fcc9d99635560c8df01ba05571f2464c1a4830e73414",\n' +
    '            "mu": "8e2a245f31f0acec8b3eb425b7d880fec610bc17a2fd4b5b654dc7797245319f95f96277408d4999c45dc68583e5f5c26eb2e29297a7351d83ec8cdceac874eeaaeff7df4905801432d26c2bbf0a45e90ac97a0eb8b9953392ab5eb5574cdb4c3b0f673e22bbe91c71787e821012d5899f5d4081089eacd5e6d467f58961ddd7eaa3de6228ecf1157fab1ce61ae4b7fd955961498724a5ad15cb04b29c7008b9d905f38587ce25a2ef7e5284cc94a2d469a59d020f90de08eff850984c86979b12045792325fb8296f54b33863854baecf295ae395b1c5c470f7b84223b4604eed37591208ad6894e8087c79cf8f4e4faf4837dd7d4271152ac83105068fba37",\n' +
    '            "n": "a596aafa6c9ecde4e4a360136816b89f8fbc43460055cef1318275ac1d6914cf73d731d6320337f3ae8ab99344ee1defe12b6a368df99774e3ee2e6efd174ea2a323f7881d1580b460a0530cc7c9006f97fa8c5890f7d66f96c499f9dc3f8729f70b9a2540e7bf98480e1c735121eaa4bfe484819cbfdff06859d24e2a332ab8ba1083dfc315437649857976c2c1c28dc86e930004e67af106e82ce94b6321b1de4abff30d68dd4174960b98d7f8cee09bc68abf3eeb93c9287031af6305020f691c67d64316d5fbb4929dc7227a3676dcf7f0589eab661b1a5a625b0fc44f1939326b952a44e9d990435f08c4d7d11cffd79303822e70dfbeacd8fec1b65fa1",\n' +
    '            "p": "d50593a10052c3c9e4fd5abedcf0de90566e7b6bff873895956cb4d8591d84733c15b111132fe04a8872257f6037ceb108018f0e98ad29a024fd96468eea2544a75ab49ae966a33324e4efecb7e2a74480b628f69a25e423660977d34c2b29fedb27ac978dcab398482886974d7feae9f330eb1dafa1e32ddb1248a233ad6d6b",\n' +
    '            "q": "c6ff32c39885b5302783180a7aae03bd48095758e8cb1c005562db28a414ec569e5a3b283476e34d32c6c77ca389062030122ff654a849d6f1b5252df567dfbe35dc7c2b2df3773c9b1776cc9798882a07aff0a42047a4ad2263f0ca8976bacff1416dabd024fe8a6ee0dba79dc1b0dd0018b7ca32371bbf9d4e76145d21be23",\n' +
    '            "pSqr": "b14247c903f608aa11e4c6962714adf4e53a017f12e18808023a18d7d39eaacfb2144c06ad9d907f1270083e73a3854371598b40e25368f13da503e24d53ca0fcc9e3dbc50777ff655f9f103ccaa0de97b4c7f27d3b0274785380ec5c1f5e147facb75778057b2ed0cee8a0259c05605c86638c69acca48c83fd691653a64a9b64e71295bca2f4bfd910c0030d29f811c49c574e09aca65ff2c70828ffde24e54eb62f90e058202355c0b13bb0fd86d93a3eeaa6b4640ff3a2d3a35599a64ec2be025489c53f2b6bdc956f719835ca36c8571f71a953484f7249e24af3aae87609c5176ff6f531ef7802b028a51a8e2e91aed239756fdb0d74853a81b3624ab9",\n' +
    '            "qSqr": "9aafc0ecbba9abab6465642474f22808c0e6bf5678b34b44c9b40af3858a85b2ec1607b81bb5e8ddefcf7785bb5a29849e144473ad99e26136ed944a02bb17ede12012fbb1f46322631d0853b27369c86529d81371b9672703d6490491e35910374ed0d758bf96a409f118051bafc1c254aefb5e93d31064e5d42e92b068a61f31c3015d98bb82a6c6b52c619ec28cb022c7ddb44cabfc780ad325338635f874e1962a275f1d67a1b0024f9f34b1267c30e35753aa39db0fe3810fd0082f9bc2b046305954e429246652c43b445eff42bb46859f1104c9a1f9aa89a15d6a348c8279f991a69e3e2fd5c471ad29b78c7c376d1eea9a9a057a95c38210003df8c9",\n' +
    '            "pMinus1": "d50593a10052c3c9e4fd5abedcf0de90566e7b6bff873895956cb4d8591d84733c15b111132fe04a8872257f6037ceb108018f0e98ad29a024fd96468eea2544a75ab49ae966a33324e4efecb7e2a74480b628f69a25e423660977d34c2b29fedb27ac978dcab398482886974d7feae9f330eb1dafa1e32ddb1248a233ad6d6a",\n' +
    '            "qMinus1": "c6ff32c39885b5302783180a7aae03bd48095758e8cb1c005562db28a414ec569e5a3b283476e34d32c6c77ca389062030122ff654a849d6f1b5252df567dfbe35dc7c2b2df3773c9b1776cc9798882a07aff0a42047a4ad2263f0ca8976bacff1416dabd024fe8a6ee0dba79dc1b0dd0018b7ca32371bbf9d4e76145d21be22",\n' +
    '            "hp": "b111e2ef542c56cdab9760ba895a053a727c429c58fa5d29571cff5cf50f9b367a55ca378f572f0edd124f3abb3498dc27f5e39c982987415344b5cad610da9e24ad539166ed87cc8218b51e977f9e8567f2b30e91f3d81f8111784f7dd3c5922f8ede87123b612df34ee60d975a73972f39753715468ef48b50082994320364",\n' +
    '            "hq": "2195bcfad263e4c3300de1ec5b96e31219bd985231e14f2e703b6eaa8638c2e0fb1a96c277822c29e180bf731d6a49cda51c8b70c028a3027befa6294c568eb1088cd60558be1751dba7d0eeff0ce18077df7a0a52e50162314271075bf05d765029d61ed9af69faa84834cffaad6630cf609e8fa2e9a7568fde0dfdd9223bdc",\n' +
    '            "qInvP": "23f3b0b1ac266cfc3965fa045396d955e3f238cfa68cdb6c3e4fb57b640de93cc1bfe6d983d8b13bab5fd644a50335d4e00bab720083a25ed1b8e07bb8d94aa682ad610982791b66a2cc3ace206308bf18c375e808320c03e4f7ff83ce57646cab98ce107b8f526a54d9a089b6257752c3f775e69a5b54394fc240789f7b6a07",\n' +
    '            "pInvQ": "a56975c8c621d06cf775361e1f1720ab2e4bbf06b6e9ccd1e5276c7e1ddc2975a33fa465bcf4b72351460809861ebc528af5a485947fa6d475c57f04a911510d2d4fa625d5355feabf6fa5dd988ba6a98fd07699cd62a34af1217fc32d865d59a117978cf675948fc698a6d7a3144aac30b8193a8f4d74690d70681683ff8247"\n' +
    '        }\n' +
    '    }'

const keyshare2 = '' +
    '{\n' +
    '    "x2": "ef67c2a1475d23b325de25c59a98a4e4e5a15e20e06026a33ec8f2feecb8d20c",\n' +
    '    "Q": {\n' +
    '        "curve": "secp256k1",\n' +
    '        "x": "7f973242ba5f6983bafe605e2dcc1243dac3dbc88a852033ecc54a9081aa651f",\n' +
    '        "y": "820645834484f758e4ae9e2f3738fb8d230be91db55d0f7f86e72bbbe5147bc8"\n' +
    '    },\n' +
    '    "pailPubKey": {\n' +
    '        "n": "a596aafa6c9ecde4e4a360136816b89f8fbc43460055cef1318275ac1d6914cf73d731d6320337f3ae8ab99344ee1defe12b6a368df99774e3ee2e6efd174ea2a323f7881d1580b460a0530cc7c9006f97fa8c5890f7d66f96c499f9dc3f8729f70b9a2540e7bf98480e1c735121eaa4bfe484819cbfdff06859d24e2a332ab8ba1083dfc315437649857976c2c1c28dc86e930004e67af106e82ce94b6321b1de4abff30d68dd4174960b98d7f8cee09bc68abf3eeb93c9287031af6305020f691c67d64316d5fbb4929dc7227a3676dcf7f0589eab661b1a5a625b0fc44f1939326b952a44e9d990435f08c4d7d11cffd79303822e70dfbeacd8fec1b65fa1",\n' +
    '        "g": "a596aafa6c9ecde4e4a360136816b89f8fbc43460055cef1318275ac1d6914cf73d731d6320337f3ae8ab99344ee1defe12b6a368df99774e3ee2e6efd174ea2a323f7881d1580b460a0530cc7c9006f97fa8c5890f7d66f96c499f9dc3f8729f70b9a2540e7bf98480e1c735121eaa4bfe484819cbfdff06859d24e2a332ab8ba1083dfc315437649857976c2c1c28dc86e930004e67af106e82ce94b6321b1de4abff30d68dd4174960b98d7f8cee09bc68abf3eeb93c9287031af6305020f691c67d64316d5fbb4929dc7227a3676dcf7f0589eab661b1a5a625b0fc44f1939326b952a44e9d990435f08c4d7d11cffd79303822e70dfbeacd8fec1b65fa2"\n' +
    '    },\n' +
    '    "cypher_x1": "337fa26568322b32e9b50eb5195c16121279ae7c323034753278849af00076ee3564c6af89c2a01544da87b7e5e1741e302cfc9e9892f547ea089afdaf2c0beac9a1aa054905bcd79ce073171c6a7d7ef32b53ecaa06b592c824ca5848dfa293da78994d1b0bc1df187a3913e12e06151f74eebdc7134dde0e808c298039839cbe1b3fb4be78ec8317f4edb709a278be6903d14e9ee24c2871e27b3249c268f8e082ee3b4d8424fa2f4391b6978d074294762c517b373826dc227b193a2a040fb296b0ba0e3deb87ad12322eba95cee9c592ff21ed8e59f53beba7a62bc74c56e67b0451688a027ecea0ad64b68a9a4191491736d4f7eec0703c9ebe2e95245ed071458ba151fe77fcb7e14b3cb16851f2447209be999547059279c81d23c07457ee8d95571765276601c82a73638e72d18b9d0a26d766ef3fafb40269d9f199c29c51183d2482e2a4ea98cb7a62453a63762df69dba01b8bf221ddea7bf67e61f2ab3e4fafaad1aa3269986abe93e14f29b6778f81701171f935abe69af5290a9977327b3f376bdb3629a4d14d75c37aa3fcd6033416f58430e5d69f35f7c9824aea81aa1dcb0c801ade5733fb6850b35026e02630ed47bdf656423eadf3cf535cc90c69a5d6bb04ab5178f3d70cb212aec7e95227fa828ac830729ce33199b09a292ad6f1180af44dab886fc360abf01bc7e552244c311e8bf5c22af0e332f"\n' +
    '}'

const testAddress = '0x731b2df5aef3ab37d0221133a00873578a49c2d7'

describe('mpcSign', ()=>{
    test('Sign', async()=>{
        console.time('Sign')

        const txObject = {
            nonce: 0,
            to: "0x83682797C5165878a17EBfB6DE7cd7F528033130",
            value: 0,
            chainId: 369,
            data: '',
            maxFeePerGas: '100',
            maxPriorityFeePerGas: '1000',
            gasLimit: 20000
        }

        try {
            const {priv: priv1, pub: pub1} = await Encryptor.generateKeyPair()
            const {priv: priv2, pub: pub2} = await Encryptor.generateKeyPair()

            const signerP1 = new SignerP1(keyshare1, Encryptor.encodeAuthPriv(priv1), Encryptor.encodeAuthPub(pub2))
            const signerP2 = new SignerP2(keyshare2, Encryptor.encodeAuthPriv(priv2), Encryptor.encodeAuthPub(pub1))

            await signerP1.createContext(txObject)

            const messsage1 = await signerP1.step1()
            const message2 = await signerP2.step1(JSON.stringify(txObject), messsage1)
            const message3 = await signerP1.step2(message2)
            const message4 = await signerP2.step2(message3)
            await signerP1.step3(message4)

            const rawTx = signerP1.exportRawTx()

            const parsedTxData = ethers.utils.parseTransaction(rawTx)
            expect(parsedTxData.from.toUpperCase()).toEqual(testAddress.toUpperCase())

        }catch (e) {
            console.error(e)
            throw e
        }
        console.timeEnd('Sign')
    })
})

describe('Verify Sign', function () {
    it('2 party sign', async function() {
        console.time('Sign')
        try {
            let m = new BN("1234567812345678123456781234567812345678123456781234567812345678")
            let p1Ctx = await TPCEcdsaSign.P1Context.createContext(keyshare1, m)
            let p2Ctx = await TPCEcdsaSign.P2Context.createContext(keyshare2, m)

            let message1 = p1Ctx.step1()
            let message2 = p2Ctx.step1(message1)
            let message3 = p1Ctx.step2(message2)
            let message4 = p2Ctx.step2(message3)
            p1Ctx.step3(message4)

            let [r, s, v] = p1Ctx.exportSig()
            console.log("r: \n", r.toString(16))
            console.log("s: \n", s.toString(16))
            console.log("v: \n", v)

            assert(verifySig(m, r, s, v, p1Ctx.keyShare1.Q))
        }catch (e) {
            console.error(e)
        }
        console.timeEnd('Sign')
    })
})