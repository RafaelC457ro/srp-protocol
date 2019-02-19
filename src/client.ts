import {BigInteger, default as bigInt} from 'big-integer';
import {Config} from './config';
import {hash, randomSalt} from './crypto';
import {Group} from './groups';
import {Identity} from './identity';
import {KeyPair} from './keypair';
import {multiplier} from './multiplier';
import {zeroLeftPad} from './zero-left-pad';

interface Verifier {
    username: string;
    salt: string;
    verifier: string;
}

export class Client {
    private readonly identity: Identity;
    private readonly config: Config;
    private readonly salt: Buffer;
    constructor(identity: Identity, config: Config) {
        this.identity = identity;
        this.config = config;
        this.salt = randomSalt();
    }

    public generateVerifier(): PromiseLike<Verifier> {
        const hashAlgorithm: string = this.config.getHashAlgorithm();
        const primeSize: number = this.config.getPrimeSize();
        const group: Group = new Group(primeSize);
        const prime: BigInteger = group.getPrime();
        const generator: BigInteger = group.getGenerator();
        const salt: Buffer = this.salt;
        const username: string = this.identity.getUserName();
        const password: string = this.identity.getPassWord();

        return hash(hashAlgorithm, new Buffer(`${username}:${password}`))
            .then((identity: Buffer) =>
                hash(hashAlgorithm, Buffer.concat([salt, identity]))
            )
            .then((credentials: Buffer) => {
                const x: BigInteger = bigInt(credentials.toString('hex'), 16);
                const verifier: BigInteger = generator.modPow(x, prime);

                return {
                    username: this.identity.getUserName(),
                    salt: bigInt(salt.toString('hex'), 16).toString(16),
                    verifier: verifier.toString(16)
                };
            });
    }

    public generatekeyPair(): Promise<KeyPair> {
        const primeSize: number = this.config.getPrimeSize();
        const group: Group = new Group(primeSize);
        const prime: BigInteger = group.getPrime();
        const generator: BigInteger = group.getGenerator();
        const privateKey: Buffer = randomSalt();

        return new Promise(
            (resolve: Function): void => {
                const publicKey: BigInteger = generator.modPow(
                    bigInt(privateKey.toString('hex'), 16),
                    prime
                );
                resolve({
                    public: publicKey.toString(16),
                    private: privateKey.toString('hex')
                });
            }
        );
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

    private generatePreMasterSecret(
        keypair: KeyPair,
        serverPublicKey: string
    ): Promise<string> {
        const hashAlgorithm: string = this.config.getHashAlgorithm();
        const primeSize: number = this.config.getPrimeSize();
        const group: Group = new Group(primeSize);
        const prime: BigInteger = group.getPrime();
        const generator: BigInteger = group.getGenerator();
        const primeLenght: number = group.getPrimeBinaryLength();
        const salt: Buffer = this.salt;
        const username: string = this.identity.getUserName();
        const password: string = this.identity.getPassWord();

        const scramblingPromise: PromiseLike<Buffer> = hash(
            hashAlgorithm,
            Buffer.concat([
                zeroLeftPad(primeLenght, Buffer.from(keypair.publicKey, 'hex')),
                zeroLeftPad(primeLenght, Buffer.from(serverPublicKey, 'hex'))
            ])
        );

        const multiplierPromise: PromiseLike<Buffer> = hash(
            hashAlgorithm,
            multiplier(prime, generator)
        );

        const credentialsPromise: PromiseLike<Buffer> = hash(
            hashAlgorithm,
            new Buffer(`${username}:${password}`)
        ).then((identity: Buffer) =>
            hash(hashAlgorithm, Buffer.concat([salt, identity]))
        );

        return Promise.all([
            scramblingPromise,
            multiplierPromise,
            credentialsPromise
        ]).then(
            ([scramblingHash, multiplierHash, credentialsHash]: Buffer[]) => {
                const credentials: BigInteger = bigInt(
                    credentialsHash.toString('hex'),
                    16
                );
                const multiplierK: BigInteger = bigInt(
                    multiplierHash.toString('hex'),
                    16
                );
                const serverPublicKeyInt: BigInteger = bigInt(
                    serverPublicKey,
                    16
                );
                const scrambling: BigInteger = bigInt(
                    scramblingHash.toString('hex'),
                    16
                );
                const keyPairPrivate: BigInteger = bigInt(
                    keypair.privateKey,
                    16
                );

                return serverPublicKeyInt
                    .minus(
                        multiplierK.multiply(
                            generator.modPow(credentials, prime)
                        )
                    )
                    .modPow(
                        keyPairPrivate.add(scrambling.multiply(credentials)),
                        prime
                    )
                    .toString(16);
            }
        );
    }

    private generateClientProof(
        clientPublicKey: string,
        serverPublicKey: string,
        premasterSecret: string
    ): PromiseLike<string> {
        const hashAlgorithm: string = this.config.getHashAlgorithm();

        return hash(hashAlgorithm, new Buffer(premasterSecret)).then(
            (premasterSecretHash: Buffer) =>
                hash(
                    hashAlgorithm,
                    new Buffer(
                        clientPublicKey +
                            serverPublicKey +
                            premasterSecretHash.toString('hex')
                    )
                ).then((buffer: Buffer) => buffer.toString('hex'))
        );
    }
}
