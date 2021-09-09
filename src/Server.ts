import {BigInteger, BigNumber, default as bigInt} from "big-integer";
import {Config} from "./Config";
import {Crypto} from "./Crypto";
import {Group} from "./Groups";
import {KeyPair} from "./Keypair";

export class Server {
    private readonly config: Config;
    private readonly passwordVerifier: BigInteger;
    private readonly crypto: Crypto;

    constructor(passwordVerifier: string, config: Config) {
        this.config = config;
        this.passwordVerifier = bigInt(passwordVerifier, 16);
        this.crypto = new Crypto();
    }

    public generateKeyPair(): PromiseLike<KeyPair> {
        const hashAlgorithm: string = this.config.getHashAlgorithm();
        const primeSize: number = this.config.getPrimeSize();
        const group: Group = new Group(primeSize);
        const N: BigInteger = group.getPrime();
        const g: BigNumber = group.getGenerator();
        const privateKey: Buffer = this.crypto.randomSalt();
        const v: BigInteger = this.passwordVerifier;
        const multiplier: Buffer = this.crypto.multiplier(N, g);

        // B = k*v + g^b % N
        return this.crypto
            .hash(hashAlgorithm, multiplier)
            .then((multiplierHash: Buffer) => {
                const k: BigNumber = bigInt(multiplierHash.toString("hex"), 16);
                const b: BigNumber = bigInt(privateKey.toString("hex"), 16);
                const B: BigNumber = k
                    .times(v)
                    .add(g.modPow(b, N))
                    .mod(N);

                return {
                    privateKey: privateKey.toString("hex"),
                    publicKey: B.toString(16)
                };
            });
    }

    /*
    TODO:
    The client key exchange message carries the client's public value
    (A).  The client calculates this value as A = g^a % N, where a is a
    random number that SHOULD be at least 256 bits in length.

    The server MUST abort the handshake with an "illegal_parameter" alert
    if A % N = 0.
    */
    public isClientValidProof(
        clientProof: string,
        keyPair: KeyPair,
        clientPublicKey: string
    ): PromiseLike<boolean> {
        return this.generatePreMasterSecret(clientPublicKey, keyPair)
            .then((preMasterSecret: string) => {
                return this.generateServerProof(
                    clientPublicKey,
                    keyPair.publicKey,
                    preMasterSecret
                );
            })
            .then((proof: string) => {
                return clientProof === proof;
            });
    }

    public generatePreMasterSecret(
        clientPublicKey: string,
        keyPair: KeyPair
    ): PromiseLike<string> {
        const hashAlgorithm: string = this.config.getHashAlgorithm();
        const primeSize: number = this.config.getPrimeSize();
        const group: Group = new Group(primeSize);
        const prime: BigInteger = group.getPrime();
        const primeLenght: number = group.getPrimeBinaryLength();
        const passwordVerifier: BigInteger = this.passwordVerifier;
        const clientPublicKeyInt: BigInteger = bigInt(clientPublicKey, 16);

        return this.crypto
            .hash(
                hashAlgorithm,
                Buffer.concat([
                    this.crypto.zeroLeftPad(
                        primeLenght,
                        Buffer.from(clientPublicKey, "hex")
                    ),
                    this.crypto.zeroLeftPad(
                        primeLenght,
                        Buffer.from(keyPair.publicKey, "hex")
                    )
                ])
            )
            .then((scramblingHash: Buffer) => {
                const scrambling: BigInteger = bigInt(
                    scramblingHash.toString("hex"),
                    16
                );
                const privateKey: BigInteger = bigInt(keyPair.privateKey, 16);

                return clientPublicKeyInt
                    .multiply(passwordVerifier.modPow(scrambling, prime))
                    .modPow(privateKey, prime)
                    .toString(16);
            });
    }

    private generateServerProof(
        clientPublicKey: string,
        serverPublicKey: string,
        premasterSecret: string
    ): PromiseLike<string> {
        const hashAlgorithm: string = this.config.getHashAlgorithm();

        return this.crypto
            .hash(hashAlgorithm, Buffer.from(premasterSecret))
            .then((premasterSecretHash: Buffer) =>
                this.crypto.hash(
                    hashAlgorithm,
                    Buffer.from(
                        clientPublicKey +
                            serverPublicKey +
                            premasterSecretHash.toString("hex")
                    )
                )
            )
            .then((buffer: Buffer) => buffer.toString("hex"));
    }
}
