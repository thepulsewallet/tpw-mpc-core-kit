import {PailPrivKey, PailPubKey} from "@safeheron/crypto-paillier";
import {HashCommitment} from "@safeheron/crypto-commitment/dist";
import BN from "bn.js";
import {PailProof, Secp256k1SchnorrProof} from "@safeheron/crypto-zkp";
import {Rand} from "@safeheron/crypto-rand";
import elliptic from "elliptic";

const Secp256k1 = new elliptic.ec('secp256k1')

type TCurve = any
type TCurvePoint = any

export class ReShare {

    private expectedStep: number
    public readonly pailPrivKey: PailPrivKey
    public readonly pailPubKey: PailPubKey
    public Q1: TCurvePoint
    public Q: TCurvePoint
    public x1: BN
    public cypher_x1: BN
    public blind: BN
    public commitment_Q1: BN
    public proof_Q1: Secp256k1SchnorrProof
    public proof_pailN: PailProof

    public constructor(pailPrivKey: PailPrivKey, pailPubKey: PailPubKey,
                       x1: BN,
                       Q1: TCurvePoint,
                       blind: BN,
                       commitment_Q1: BN,
                       cypher_x1: BN,
                       proof_Q1: Secp256k1SchnorrProof,
                       proof_pailN: PailProof) {
        this.pailPrivKey = pailPrivKey
        this.pailPubKey = pailPubKey
        this.x1 = x1
        this.Q1 = Q1
        this.blind = blind
        this.commitment_Q1 = commitment_Q1
        this.cypher_x1 = cypher_x1
        this.proof_Q1 = proof_Q1
        this.proof_pailN = proof_pailN
        this.expectedStep = 1
    }

    public static async reSharing(pailPrivKey: PailPrivKey, pailPubKey: PailPubKey, _x1: string, Q: TCurvePoint): Promise<any> {
        let x1 = new BN(_x1, 16)
        let Q1 = Secp256k1.g.mul(x1)
        let blind = await Rand.randomBN(32)
        let commitment_Q1 = HashCommitment.createComWithBlindFromCurvePoint(Q1, blind)

        let proof_Q1 = await Secp256k1SchnorrProof.prove(x1)
        let proof_pailN = PailProof.prove(pailPrivKey, new BN(1), Q1.getX(), Q1.getY())
        let cypher_x1 = await pailPubKey.encrypt(x1)

        return new ReShare(pailPrivKey, pailPubKey, x1, Q1, blind, commitment_Q1, cypher_x1, proof_Q1, proof_pailN)
    }
}