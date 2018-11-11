import {BigInteger, default as bigInt} from 'big-integer';
import leftPad from 'left-pad';
import {Config} from './config';
import {hash, randomSalt} from './crypto';
import {Group} from './groups';
import {KeyPair} from './keypair';

export class Server {
    private config: Config;
    private passwordVerifier: BigInteger;
    constructor(passwordVerifier: string, config: Config) {
        this.config = config;
        this.passwordVerifier = bigInt(passwordVerifier);
    }

    public generateKeyPair(): PromiseLike<KeyPair> {
        const hashAlgorithm = this.config.getHashAlgorithm();
        const primeSize = this.config.getPrimeSize();
        const group = new Group(primeSize);
        const prime = group.getPrime();
        const generator = group.getGenerator();
        const primeLength = group.getPrimeLength();
        const privateKey = randomSalt();
        const passwordVerifier = this.passwordVerifier;

        return hash(
            hashAlgorithm,
            prime.toString() + leftPad(generator.toString(), primeLength, '0')
        ).then((multiplierHash: string) => {
            const publicKey = bigInt(multiplierHash, 16)
                .times(passwordVerifier)
                .add(generator.modPow(privateKey, prime));
            return {
                public: publicKey.toString(),
                private: privateKey.toString()
            };
        });
    }

    public proof(
        clientProof: string,
        keyPair: KeyPair,
        clientPublicKey: string
    ) {
        return this.generatePreMasterSecret(clientPublicKey, keyPair).then(
            preMasterKey =>
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
        clientPublicKey
    ): PromiseLike<boolean> {
        return this.generatePreMasterSecret(clientPublicKey, keyPair)
            .then(preMasterSecret => {
                return this.generateServerProof(
                    clientPublicKey,
                    keyPair.public,
                    preMasterSecret
                );
            })
            .then(proof => {
                return clientProof === proof;
            });
    }

    private generatePreMasterSecret(
        clientPublicKey: string,
        keyPair: KeyPair
    ): PromiseLike<string> {
        const hashAlgorithm = this.config.getHashAlgorithm();
        const primeSize = this.config.getPrimeSize();
        const group = new Group(primeSize);
        const prime = group.getPrime();
        const primeLenght = group.getPrimeLength();
        const passwordVerifier = this.passwordVerifier;
        const clientPublicKeyInt = bigInt(clientPublicKey);

        return hash(
            hashAlgorithm,
            leftPad(clientPublicKey, primeLenght, '0') +
                leftPad(keyPair.public, primeLenght, '0')
        ).then((scramblingHash: string) => {
            const scrambling = bigInt(scramblingHash, 16);
            const privateKey = bigInt(keyPair.private);
            return clientPublicKeyInt
                .multiply(passwordVerifier.modPow(scrambling, prime))
                .modPow(privateKey, prime)
                .toString();
        });
    }

    private generateServerProof(
        clientProof: string,
        clientPublicKey: string,
        premasterSecret: string
    ) {
        const hashAlgorithm = this.config.getHashAlgorithm();
        return hash(hashAlgorithm, premasterSecret).then(
            (premasterSecretHash: string) =>
                hash(
                    hashAlgorithm,
                    clientPublicKey + clientProof + premasterSecretHash
                )
        );
    }
}
