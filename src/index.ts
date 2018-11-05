import {BigInteger, default as bigInt} from 'big-integer';
import {getGroup} from './groups';

function randomSalt(): string {
    const array = new Uint8Array(32);
    return bigInt(
        Buffer.from(crypto.getRandomValues(array)).toString('hex'),
        16
    ).toString();
}

function hash(hashAlgorithm: string, text: string): Promise<String> {
    return new Promise(resolve => {
        const buffer = new TextEncoder().encode(text);
        return crypto.subtle.digest(hashAlgorithm, buffer).then(function(hash) {
            resolve(Buffer.from(hash).toString('hex'));
        });
    });
}

interface Config {
    primeSize: string;
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
    /*
     x = SHA1(s | SHA1(I | ":" | P))
     v = g^x % N
    */
    public generateVerifier({username, password}: Identity): Promise<Verifier> {
        return new Promise((resolve, reject) => {
            const {hashAlgorithm, primeSize} = this.config;
            const {prime, generator} = getGroup(primeSize);
            const salt = randomSalt();

            hash(hashAlgorithm, `${username}:${password}`)
                .then((hashIdentity: string) =>
                    hash(hashAlgorithm, salt + hashIdentity)
                )
                .then((xHash: string) => {
                    const x: BigInteger = bigInt(xHash, 16);

                    const {remainder: verifier} = generator
                        .modPow(x, prime)
                        .divmod(prime);
                    resolve({
                        username,
                        salt,
                        verifier: verifier.toString()
                    });
                })
                .catch(err => reject(err));
        });
    }
}
