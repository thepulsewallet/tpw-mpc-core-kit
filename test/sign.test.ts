import { ethers } from 'ethers'

import Encryptor from '../src/enc/encryptor'
import SignerP1 from '../src/sign/signer-p1'
import SignerP2 from '../src/sign/signer-p2'
import {TPCEcdsaSign} from "@safeheron/two-party-ecdsa-js";
import * as BN from "bn.js";
import {verifySig} from "../src/sign/verify";
import * as assert from "assert";

const keyshare1 = '' +
    '{\n' +
    '    "x1": "8493ca197311af71fc9ad1643417424d7cefd4f7796e2ae7ecbd66480f0939b4",\n' +
    '    "Q": {\n' +
    '        "curve": "secp256k1",\n' +
    '        "x": "a1be7ebf6b7cfe3c82df02937fdd45e75a876397325e4f86d8e77850b453d74",\n' +
    '        "y": "3041ec5158bba7155f4fa773a2a341f102cf0f65d97b78040e0f9e8328ee67f6"\n' +
    '    },\n' +
    '    "pailPubKey": {\n' +
    '        "n": "64515dcb56d8f1fbf3ea90d464ac0764e2e7229067f8936a1384b48c6335a3acf268a85015ce37d31e3aa18f2beff972d24fcbc0b959ce040d4db69e432675cfc1c5d5a2b73655c5c01923e7f7bf73aced5f3ef6df5afd04db9df25dc8a3e1a01b9c2ae3f8c26e084504a3e8a44c3ec6631d92d93124f45353b433a682f762923364acc85dd38f28e706059908c29c9743802a0db9b94f84890cdc64c41b7a31f22ae11cf5e7037f6e79b00594813259fa340995886caf189fee292f43dc7dc4c3cefb0875bb36d8f2c2630f2fe64c9bfa48d153489abecd663407fea94147650829a83cebd310da7ba0fc184913f0cedba2bd509e193a624da92d52cf33d10b",\n' +
    '        "g": "64515dcb56d8f1fbf3ea90d464ac0764e2e7229067f8936a1384b48c6335a3acf268a85015ce37d31e3aa18f2beff972d24fcbc0b959ce040d4db69e432675cfc1c5d5a2b73655c5c01923e7f7bf73aced5f3ef6df5afd04db9df25dc8a3e1a01b9c2ae3f8c26e084504a3e8a44c3ec6631d92d93124f45353b433a682f762923364acc85dd38f28e706059908c29c9743802a0db9b94f84890cdc64c41b7a31f22ae11cf5e7037f6e79b00594813259fa340995886caf189fee292f43dc7dc4c3cefb0875bb36d8f2c2630f2fe64c9bfa48d153489abecd663407fea94147650829a83cebd310da7ba0fc184913f0cedba2bd509e193a624da92d52cf33d10c"\n' +
    '    },\n' +
    '    "pailPrivKey": {\n' +
    '        "lambda": "64515dcb56d8f1fbf3ea90d464ac0764e2e7229067f8936a1384b48c6335a3acf268a85015ce37d31e3aa18f2beff972d24fcbc0b959ce040d4db69e432675cfc1c5d5a2b73655c5c01923e7f7bf73aced5f3ef6df5afd04db9df25dc8a3e1a01b9c2ae3f8c26e084504a3e8a44c3ec6631d92d93124f45353b433a682f76290f20506918e770157545f6183cb997a0b4e7163b5e4b1f602f789e6c04a838e5fdf583f350ec6b633b5ca217bf1947564e34a49d2479ff39c8a07eb631ac6c101337b9481d619457fcf82954f8563482efc90c731e54f9e9a8f1e7abab2c1095cdcc9cc56600800d9beef91ebbc000e29c4d8b54af85ac4b88923cd8f6cc58478",\n' +
    '        "mu": "2b9fd5bc0afc95771d7dcbc58bdcf3d1f3692ec7e8eed249795d260e0b4d062d7ae3e3df8e001c618f24386b66acdc4ec9f2ebff63e616c10f966e91b10e318a53dce020adff6b953ef78c6ad1da8ae96dc2ccf61d32c8d5f7234b4d971dbe3a91b5e28fc13c55a02b61eae6eee8cab59b0f1368bc39f23fb5d29932e5631b732dc5a80d060746fff2af9592c70bc5b58408448d623cf8928f9bd0827bd6f14343b164345f12bd63b6f502de139c144ba4816f45288d7fb3314398ab9b65398221d7c9828351eaf1ee2a80822b18c2515381900bcec1d3c4ee50e8b759f650320a2626820790a0d8928285a59f926b349da04eeb98554706a6350af7952f69e9",\n' +
    '        "n": "64515dcb56d8f1fbf3ea90d464ac0764e2e7229067f8936a1384b48c6335a3acf268a85015ce37d31e3aa18f2beff972d24fcbc0b959ce040d4db69e432675cfc1c5d5a2b73655c5c01923e7f7bf73aced5f3ef6df5afd04db9df25dc8a3e1a01b9c2ae3f8c26e084504a3e8a44c3ec6631d92d93124f45353b433a682f762923364acc85dd38f28e706059908c29c9743802a0db9b94f84890cdc64c41b7a31f22ae11cf5e7037f6e79b00594813259fa340995886caf189fee292f43dc7dc4c3cefb0875bb36d8f2c2630f2fe64c9bfa48d153489abecd663407fea94147650829a83cebd310da7ba0fc184913f0cedba2bd509e193a624da92d52cf33d10b",\n' +
    '        "p": "ac78c89837c0c4230dc0e76f4c1f43e142129d682f54e1a4d06dddf140f0d0527891074c96d73684e1390b12257bdfdeab60df1b708a6a575c1d780606ec1d012677a20724975911230ea56b3a3a683208e6e9fab7f2859814725c63be067f9c389da1281c5a9761e398468b386f00f35cb4507f0a419fcbf54c2f01ed69b0a5",\n' +
    '        "q": "94e6dd9e979bc9ae84e5bca5f109deaab2fc28efa5b277dcc11517b338a71b7f9a419a9b504916c6d77683777d70dd166b88e0a7d0425124b9c8c5c622299fc269dbc47f7b0a98480031285470489c3af4d12026ab589a9ac2a330e03879be6bf2c23abe6f70789ed91923a154a4e1b1ba15b7869b7cd5ddcf3930c175049bef",\n' +
    '        "pSqr": "7432868936cd7de66edc30622015524ab2ae039fb00024578389847a7947cacfaf30c19cc597143beea81824bc60f42b159b2c4795fa8181e7f7247c765bc72d63659c6ebe1537095309142ae131b3b72a074f9d64767061c8706772b34a08235dd57bb13f72601fd7a6b193e0060313ff90e304ac8320b9ded376b58568b0832034356e430209244e85bf5c104a421b7e511ec3251ebe3378ba9ab719a22cc7b725df6f2c35212010faebcc33da6544dcc4bfde74c1e1d92fa8420ebdc08fa87ca0e2785c6725bfb921883f33ba70b2435dcf32901d985c64b648d704c406d6387cac600e5ca02aca0057ad0a8886b037150fcc090813bb39d4d3fde33d4a59",\n' +
    '        "qSqr": "569bc072581fc122a78dda89452b5c99ef2105974b88e4cc58952c89e3e31622912beb66f678b36a3552569abadfe22e435e1281cb576a15ad104f140ceb1e39ff7ae48328dceda46a30874f8ae1cec432f811fbc279df4de981822ff807ab9be42fa8ced0c7e03e0008f3ba3b89cf84c1eb850d451faa5df9987cb781563e135a7a7df592dc4ea5ee819e14d659f9007b9683b240bba490affe1b799248d506f03ba1643e3affeac3f93ae341891de64dab3845d7e9aa2291654b31280732219427c21c61deaef52302b60e9bc77e6795bd70dd8f097e08721286fadd4049b1d551e2497ec6be2f9cf6709ed8881f2013b385dbc9a59ef35357f4fbb4734921",\n' +
    '        "pMinus1": "ac78c89837c0c4230dc0e76f4c1f43e142129d682f54e1a4d06dddf140f0d0527891074c96d73684e1390b12257bdfdeab60df1b708a6a575c1d780606ec1d012677a20724975911230ea56b3a3a683208e6e9fab7f2859814725c63be067f9c389da1281c5a9761e398468b386f00f35cb4507f0a419fcbf54c2f01ed69b0a4",\n' +
    '        "qMinus1": "94e6dd9e979bc9ae84e5bca5f109deaab2fc28efa5b277dcc11517b338a71b7f9a419a9b504916c6d77683777d70dd166b88e0a7d0425124b9c8c5c622299fc269dbc47f7b0a98480031285470489c3af4d12026ab589a9ac2a330e03879be6bf2c23abe6f70789ed91923a154a4e1b1ba15b7869b7cd5ddcf3930c175049bee",\n' +
    '        "hp": "5dc3beeab592b40d6a33871515e7c58b665d7fdfe745899d9ec3d7903a046c59d87270e48f195615d91d0572f5611ef45e985c69c18decb740ead652cecff8460d68309af547ac7ce195a4629dbbcec15f922642c6b2a26b5db6ad534c01e7c28ad06b03b4318c0690151d80f50f29b19e3d9fd73a96c0d0b077103ea61355b1",\n' +
    '        "hq": "43f3789338f8ea229d7bd69d18f38e110370a500ce9cc110b31bd09edf5bb47938b65feaf5937b055fc47d50f257207eb4f4a2f196d4b78e5b20618eb88779c0265bf3e4ef525a1975084c1811548e1d5f3c6cf49be619c23fcd14124896b99271afe1d510e549e704b6a6c1e9c456c3636b645172130a3882dfbbbfd01b41af",\n' +
    '        "qInvP": "4eb509ad822e1015a38d605a36377e55dbb51d88480f580731aa066106ec63f8a01e966807bde06f081c059f301ac0ea4cc882b1aefc7da01b32a1b3381c24bb190f716c2f4fac94417901089c7e9970a954c3b7f13fe32cb6bbaf10720497d9adcd362468290b5b5383290a435fd741be76b0a7cfaadefb44d51ec347565af4",\n' +
    '        "pInvQ": "50f3650b5ea2df8be769e608d8165099af8b83eed715b6cc0df94714594b6706618b3ab05ab59bc177b206268b19bc97b6943db6396d99965ea8643769a22602437fd09a8bb83e2e8b28dc3c5ef40e1d9594b3320f7280d882d61ccdefe304d9811258e95e8b2eb7d4627cdf6ae08aee56aa53352969cba54c597501a4e95a40"\n' +
    '    }\n' +
    '}'

const keyshare2 = '' +
    '{\n' +
    '    "x2": "32468c05e7441d165450805c9030a5bc1fb00e7f392780bacd2875e717cf9343",\n' +
    '    "Q": {\n' +
    '        "curve": "secp256k1",\n' +
    '        "x": "a1be7ebf6b7cfe3c82df02937fdd45e75a876397325e4f86d8e77850b453d74",\n' +
    '        "y": "3041ec5158bba7155f4fa773a2a341f102cf0f65d97b78040e0f9e8328ee67f6"\n' +
    '    },\n' +
    '    "pailPubKey": {\n' +
    '        "n": "64515dcb56d8f1fbf3ea90d464ac0764e2e7229067f8936a1384b48c6335a3acf268a85015ce37d31e3aa18f2beff972d24fcbc0b959ce040d4db69e432675cfc1c5d5a2b73655c5c01923e7f7bf73aced5f3ef6df5afd04db9df25dc8a3e1a01b9c2ae3f8c26e084504a3e8a44c3ec6631d92d93124f45353b433a682f762923364acc85dd38f28e706059908c29c9743802a0db9b94f84890cdc64c41b7a31f22ae11cf5e7037f6e79b00594813259fa340995886caf189fee292f43dc7dc4c3cefb0875bb36d8f2c2630f2fe64c9bfa48d153489abecd663407fea94147650829a83cebd310da7ba0fc184913f0cedba2bd509e193a624da92d52cf33d10b",\n' +
    '        "g": "64515dcb56d8f1fbf3ea90d464ac0764e2e7229067f8936a1384b48c6335a3acf268a85015ce37d31e3aa18f2beff972d24fcbc0b959ce040d4db69e432675cfc1c5d5a2b73655c5c01923e7f7bf73aced5f3ef6df5afd04db9df25dc8a3e1a01b9c2ae3f8c26e084504a3e8a44c3ec6631d92d93124f45353b433a682f762923364acc85dd38f28e706059908c29c9743802a0db9b94f84890cdc64c41b7a31f22ae11cf5e7037f6e79b00594813259fa340995886caf189fee292f43dc7dc4c3cefb0875bb36d8f2c2630f2fe64c9bfa48d153489abecd663407fea94147650829a83cebd310da7ba0fc184913f0cedba2bd509e193a624da92d52cf33d10c"\n' +
    '    },\n' +
    '    "cypher_x1": "9f7a0899a087ae44553ce7159d61017a1e4d7debfc5285b768017f504a4a19813f01536df20ec2f080f893cae996d4894d432e3450b4dde2c59bee5bbff25f9d57a3ac32dcbf3a897108feab15c13daff05b5ce9192f76cfc677a04f1887ff59cddc0937f9aca4be958b22076a1c9d55ea34aaacbf820ee2ec2aba129e62150d55bb590152e83e7227f3c1e0227aabf74c53ea37c56794b1aca7c3261a6031d582c9bd7c6fb13a36fbff689a9fa94ee8ec51898bde8d67e1bc70e79101b8bdeecd37dd8cc9a4f0db19a5066804d6c4d33118f67f2ccb18128e513af284a2710f9028d3e5f5b914ec3b7b7f8339e0acce6b76c62cf82061f53968b028e17793e99ecf4555b60ba19ce0df2f59857e675a5190b94519acf501883f49be79f5ca628db54a66288dda3b7d3a8c2675e11d70d0d5e50f9d6e9c44aacac5883e4cb63671f5ffa29de605ed1a62fb00ce738b15cbe4faaff45dd4e79937e2b8acc1ffa758286018674cc8f4b71989f46eb6edbea0e530f212d770e2dda9c384ae6945b9d6e4c5c1d081d3f350f6dcf17357325780368798b4383c46efcebf20ab88e0b8fbc9cd9cd21211fac243335a9d42c33d5a94b88766073bc07cc07e5694f0a26e21daab5be90b0e8a6ed16f3227b348ed1b7e4ead25ac24adf7f8570d758941d40b65b28b88a30d4116e5e14309f6b02617373afd2ed9eff6f9dc1c8b4f141ae"\n' +
    '}'

const testAddress = '0x731b2df5aef3ab37d0221133a00873578a49c2d7'

describe('mpcSign', ()=>{
    test('Sign', async()=>{
        console.time('Sign')

        const txObject = {
            nonce: 0,
            to: "0x83682797C5165878a17EBfB6DE7cd7F528033130",
            value: 0,
            chainId: 3,
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

describe('Verify Sign', async function () {
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
        this.timeout(20000)
    })
})