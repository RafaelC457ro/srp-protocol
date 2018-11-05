import {BigInteger, default as bigInt} from 'big-integer';
import {Group, getGroup} from './groups';

function randomSalt(): string {
    const array = new Uint8Array(32);
    const random = Buffer.from(crypto.getRandomValues(array)).toString('hex');
    return bigInt(random, 16).toString();
}

function hash(hashAlgorithm: string, text: string): PromiseLike<String> {
    const buffer = new TextEncoder().encode(text);
    return crypto.subtle
        .digest(hashAlgorithm, buffer)
        .then(hash => Buffer.from(hash).toString('hex'));
}

interface Config {
    primeSize: number;
    hashAlgorithm: string; // SHA-1 (not supported by Microsoft Edge), SHA-256, SHA-384, and SHA-512.
}

interface Identity {
    username: string;
    password: string;
}

interface Verifier {
    username: string;
    salt: string;
    verifier: string;
}
interface KeyPair {
    private: string;
    public: string;
}

export class Srp {
    private config: Config;
    constructor(config: Config) {
        this.config = config;
    }

    public generateVerifier({
        username,
        password
    }: Identity): PromiseLike<Verifier> {
        const {hashAlgorithm, primeSize} = this.config;
        const {prime, generator}: Group = getGroup(primeSize);
        const salt = randomSalt();

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
                    username,
                    salt,
                    verifier: verifier.toString()
                };
            });
    }

    public serverKeyPair(passwordVerifier: string): PromiseLike<KeyPair> {
        const {hashAlgorithm, primeSize} = this.config;
        const {prime, generator}: Group = getGroup(primeSize);
        const privateKey = randomSalt();

        return hash(
            hashAlgorithm,
            prime.toString() + generator.toString()
        ).then((multiplierHash: string) => {
            const publicKey = bigInt(multiplierHash, 16)
                .times(bigInt(passwordVerifier))
                .add(generator.modPow(privateKey, prime));
            return {
                public: publicKey.toString(),
                private: privateKey.toString()
            };
        });
    }

    public clientKeyPair(): KeyPair {
        const {primeSize} = this.config;
        const {prime, generator}: Group = getGroup(primeSize);
        const privateKey = randomSalt();
        const publicKey = generator.modPow(privateKey, prime);
        return {
            public: publicKey.toString(),
            private: privateKey.toString()
        };
    }
}
