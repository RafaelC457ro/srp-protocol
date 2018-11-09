import {BigInteger, default as bigInt} from 'big-integer';
import leftPad from 'left-pad';
import {hash, randomSalt} from './crypto';
import {Group} from './groups';
import {Identity} from './identity';
import {Config} from './config';
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
            .then((xHash: string) => {
                const x: BigInteger = bigInt(xHash, 16);
                const {remainder: verifier} = generator
                    .modPow(x, prime)
                    .divmod(prime);

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

    public generatePremasterSecret(
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
            leftPad(keypair.public, primeLenght) +
                leftPad(serverPublicKey, primeLenght)
        );

        const multiplierPromise = hash(
            hashAlgorithm,
            prime.toString() + leftPad(generator.toString(), primeLenght)
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
            ([scramblingHash, multiplierHash, credentialsHash]: Array<
                string
            >) => {
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
}
