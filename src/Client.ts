import {BigInteger, default as bigInt} from "big-integer";
import {Config} from "./Config";
import {Crypto} from "./Crypto";
import {Group} from "./Groups";
import {Identity} from "./Identity";
import {KeyPair} from "./Keypair";
import {Verifier} from "./Verifier";

export class Client {
    private readonly identity: Identity;
    private readonly config: Config;
    private readonly salt: Buffer;
    private readonly crypto: Crypto;

    constructor(name: string, password: string, config: Config) {
        this.identity = new Identity(name, password);
        this.crypto = new Crypto();
        this.config = config;
        this.salt = this.crypto.randomSalt(); // salt should be provida by server
    }

    public generateVerifier(): PromiseLike<Verifier> {
        const primeSize: number = this.config.getPrimeSize();
        const group: Group = new Group(primeSize);
        const prime: BigInteger = group.getPrime();
        const generator: BigInteger = group.getGenerator();
        const salt: Buffer = this.salt;

        return this.calcX().then((credentials: Buffer) => {
            const x: BigInteger = bigInt(credentials.toString("hex"), 16);
            const verifier: BigInteger = generator.modPow(x, prime);

            return {
                username: this.identity.getUserName(),
                salt: bigInt(salt.toString("hex"), 16).toString(16),
                verifier: verifier.toString(16)
            };
        });
    }

    public generatekeyPair(): Promise<KeyPair> {
        const primeSize: number = this.config.getPrimeSize();
        const group: Group = new Group(primeSize);
        const prime: BigInteger = group.getPrime();
        const generator: BigInteger = group.getGenerator();
        const privateKey: Buffer = this.crypto.randomSalt();

        return new Promise((resolve) => {
            const publicKey: BigInteger = generator.modPow(
                bigInt(privateKey.toString("hex"), 16),
                prime
            );

            resolve({
                publicKey: publicKey.toString(16),
                privateKey: privateKey.toString("hex")
            });
        });
    }

    public proof(
        clientKeyPair: KeyPair,
        serverPublicKey: string
    ): PromiseLike<string> {
        return this.generatePreMasterSecret(
            clientKeyPair,
            serverPublicKey
        ).then((premasterSecret: string) =>
            this.generateClientProof(
                clientKeyPair.publicKey,
                serverPublicKey,
                premasterSecret
            )
        );
    }

    public generatePreMasterSecret(
        keypair: KeyPair,
        serverPublicKey: string
    ): Promise<string> {
        const hashAlgorithm: string = this.config.getHashAlgorithm();
        const primeSize: number = this.config.getPrimeSize();
        const group: Group = new Group(primeSize);
        const N: BigInteger = group.getPrime();
        const g: BigInteger = group.getGenerator();

        const scramblingPromise: PromiseLike<Buffer> = this.calcU(
            keypair.publicKey,
            serverPublicKey
        );

        const multiplierPromise: PromiseLike<Buffer> = this.crypto.hash(
            hashAlgorithm,
            this.crypto.multiplier(N, g)
        );

        const credentialsPromise: PromiseLike<Buffer> = this.calcX();

        return Promise.all([
            scramblingPromise,
            multiplierPromise,
            credentialsPromise
        ]).then(([uBin, kBin, xBin]: Buffer[]) => {
            const x: BigInteger = bigInt(xBin.toString("hex"), 16);
            const k: BigInteger = bigInt(kBin.toString("hex"), 16);
            const u: BigInteger = bigInt(uBin.toString("hex"), 16);

            const a: BigInteger = bigInt(keypair.privateKey, 16);
            const B: BigInteger = bigInt(serverPublicKey, 16);

            // (B - (k * g^x)) ^ (a + (u * x)) % N
            // Because we do operation in modulo N we can get: (kv + g^b) < kv
            const intern: BigInteger = k.multiply(g.modPow(x, N)).mod(N);

            const i: BigInteger = B.greater(intern)
                ? B.subtract(intern).mod(N)
                : N.add(B.subtract(intern)).mod(N);

            return i
                .modPow(a.add(u.multiply(x)), N)
                .mod(N)
                .toString(16);
        });
    }

    public calcU(
        clientPublicKey: string,
        serverPublicKey: string
    ): PromiseLike<Buffer> {
        const hashAlgorithm: string = this.config.getHashAlgorithm();
        const primeSize: number = this.config.getPrimeSize();
        const group: Group = new Group(primeSize);
        const primeLenght: number = group.getPrimeBinaryLength();

        return this.crypto.hash(
            hashAlgorithm,
            Buffer.concat([
                this.crypto.zeroLeftPad(
                    primeLenght,
                    Buffer.from(clientPublicKey, "hex")
                ),
                this.crypto.zeroLeftPad(
                    primeLenght,
                    Buffer.from(serverPublicKey, "hex")
                )
            ])
        );
    }

    public calcX(): PromiseLike<Buffer> {
        const hashAlgorithm: string = this.config.getHashAlgorithm();
        const salt: Buffer = this.salt;
        const username: string = this.identity.getUserName();
        const password: string = this.identity.getPassWord();

        return this.crypto
            .hash(
                hashAlgorithm,
                Buffer.concat([
                    Buffer.from(username),
                    Buffer.from(":"),
                    Buffer.from(password)
                ])
            )
            .then((identity: Buffer) =>
                this.crypto.hash(hashAlgorithm, Buffer.concat([salt, identity]))
            );
    }

    private generateClientProof(
        clientPublicKey: string,
        serverPublicKey: string,
        premasterSecret: string
    ): PromiseLike<string> {
        const hashAlgorithm: string = this.config.getHashAlgorithm();

        return this.crypto
            .hash(hashAlgorithm, Buffer.from(premasterSecret))
            .then((premasterSecretHash: Buffer) => {
                const s: string = `${clientPublicKey}${serverPublicKey}${premasterSecretHash.toString(
                    "hex"
                )}`;

                return this.crypto.hash(hashAlgorithm, Buffer.from(s));
            })
            .then((buffer: Buffer) => buffer.toString("hex"));
    }
}
