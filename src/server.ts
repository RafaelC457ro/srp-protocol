import {BigInteger, BigNumber, default as bigInt} from 'big-integer';
import {Config} from './config';
import {hash, randomSalt} from './crypto';
import {Group} from './groups';
import {KeyPair} from './keypair';
import {multiplier} from './multiplier';
import {zeroLeftPad} from './zero-left-pad';

export class Server {
    private readonly config: Config;
    private readonly passwordVerifier: BigInteger;
    constructor(passwordVerifier: string, config: Config) {
        this.config = config;
        this.passwordVerifier = bigInt(passwordVerifier, 16);
    }

    public generateKeyPair(): PromiseLike<KeyPair> {
        const hashAlgorithm: string = this.config.getHashAlgorithm();
        const primeSize: number = this.config.getPrimeSize();
        const group: Group = new Group(primeSize);
        const prime: BigInteger = group.getPrime();
        const generator: BigNumber = group.getGenerator();
        const privateKey: Buffer = randomSalt();
        const passwordVerifier: BigInteger = this.passwordVerifier;

        return hash(hashAlgorithm, multiplier(prime, generator)).then(
            (multiplierHash: Buffer) => {
                const publicKey: BigInteger = bigInt(
                    multiplierHash.toString('hex'),
                    16
                )
                    .times(passwordVerifier)
                    .add(
                        generator.modPow(
                            bigInt(privateKey.toString('hex'), 16),
                            prime
                        )
                    );

                return {
                    publicKey: publicKey.toString(16),
                    privateKey: privateKey.toString('hex')
                };
            }
        );
    }

    public proof(
        clientProof: string,
        keyPair: KeyPair,
        clientPublicKey: string
    ): PromiseLike<string> {
        return this.generatePreMasterSecret(clientPublicKey, keyPair).then(
            (preMasterKey: string) =>
                this.generateServerProof(
                    clientProof,
                    clientPublicKey,
                    preMasterKey
                )
        );
    }

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

    private generatePreMasterSecret(
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

        return hash(
            hashAlgorithm,
            Buffer.concat([
                zeroLeftPad(primeLenght, Buffer.from(clientPublicKey, 'hex')),
                zeroLeftPad(primeLenght, Buffer.from(keyPair.publicKey, 'hex'))
            ])
        ).then((scramblingHash: Buffer) => {
            const scrambling: BigInteger = bigInt(
                scramblingHash.toString('hex'),
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

        return hash(hashAlgorithm, new Buffer(premasterSecret))
            .then((premasterSecretHash: Buffer) =>
                hash(
                    hashAlgorithm,
                    new Buffer(
                        clientPublicKey +
                            serverPublicKey +
                            premasterSecretHash.toString('hex')
                    )
                )
            )
            .then((buffer: Buffer) => buffer.toString('hex'));
    }
}
