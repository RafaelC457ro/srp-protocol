import {BigInteger, default as bigInt} from 'big-integer';
import leftPad from 'left-pad';
import {Config} from './config';
import {hash, randomSalt} from './crypto';
import {Group} from './groups';
import {Identity} from './identity';
import {KeyPair} from './keypair';

interface Verifier {
    username: string;
    salt: string;
    verifier: string;
}

export class Client {
    private identity: Identity;
    private config: Config;
    private salt: string;
    constructor(identity: Identity, config: Config) {
        this.identity = identity;
        this.config = config;
        this.salt = randomSalt();
    }

    public generateVerifier(): PromiseLike<Verifier> {
        const hashAlgorithm = this.config.getHashAlgorithm();
        const primeSize = this.config.getPrimeSize();
        const group = new Group(primeSize);
        const prime = group.getPrime();
        const generator = group.getGenerator();
        const salt = this.salt;
        const username = this.identity.getUserName();
        const password = this.identity.getPassWord();

        return hash(hashAlgorithm, `${username}:${password}`)
            .then((hashIdentity: string) =>
                hash(hashAlgorithm, salt + hashIdentity)
            )
            .then((credentials: string) => {
                console.log(credentials);
                const x = bigInt(credentials, 16);
                const verifier = generator.modPow(x, prime);

                return {
                    username: this.identity.getUserName(),
                    salt,
                    verifier: verifier.toString()
                };
            });
    }

    public generatekeyPair(): Promise<KeyPair> {
        const primeSize = this.config.getPrimeSize();
        const group = new Group(primeSize);
        const prime = group.getPrime();
        const generator = group.getGenerator();
        const privateKey = randomSalt();

        return new Promise(resolve => {
            const publicKey = generator.modPow(privateKey, prime);
            resolve({
                public: publicKey.toString(),
                private: privateKey.toString()
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
        ).then(premasterSecret =>
            this.generateClientProof(
                clientKeyPair.public,
                serverPublicKey,
                premasterSecret
            )
        );
    }

    private generatePreMasterSecret(
        keypair: KeyPair,
        serverPublicKey: string
    ): Promise<string> {
        const hashAlgorithm = this.config.getHashAlgorithm();
        const primeSize = this.config.getPrimeSize();
        const group = new Group(primeSize);
        const prime = group.getPrime();
        const generator = group.getGenerator();
        const primeLenght = group.getPrimeLength();
        const salt = this.salt;
        const username = this.identity.getUserName();
        const password = this.identity.getPassWord();

        const scramblingPromise = hash(
            hashAlgorithm,
            leftPad(keypair.public, primeLenght, '0') +
                leftPad(serverPublicKey, primeLenght, '0')
        );

        const multiplierPromise = hash(
            hashAlgorithm,
            prime.toString() + leftPad(generator.toString(), primeLenght, '0')
        );

        const credentialsPromise = hash(
            hashAlgorithm,
            `${username}:${password}`
        ).then((hashIdentity: string) =>
            hash(hashAlgorithm, salt + hashIdentity)
        );

        return Promise.all([
            scramblingPromise,
            multiplierPromise,
            credentialsPromise
        ]).then(
            ([scramblingHash, multiplierHash, credentialsHash]: string[]) => {
                const credentials = bigInt(credentialsHash, 16);
                const multiplier = bigInt(multiplierHash, 16);
                const serverPublicKeyInt = bigInt(serverPublicKey);
                const scrambling = bigInt(scramblingHash, 16);
                const keyPairPrivate = bigInt(keypair.private);

                return generator
                    .modPow(credentials, prime)
                    .multiply(multiplier)
                    .minus(serverPublicKeyInt)
                    .modPow(
                        keyPairPrivate.add(scrambling.multiply(credentials)),
                        prime
                    )
                    .toString();
            }
        );
    }

    private generateClientProof(
        clientPublicKey: string,
        serverPublicKey: string,
        premasterSecret: string
    ): PromiseLike<string> {
        const hashAlgorithm = this.config.getHashAlgorithm();

        return hash(hashAlgorithm, premasterSecret).then(
            (premasterSecretHash: string) =>
                hash(
                    hashAlgorithm,
                    clientPublicKey + serverPublicKey + premasterSecretHash
                )
        );
    }
}
