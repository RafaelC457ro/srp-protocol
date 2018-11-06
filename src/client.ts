import {BigInteger, default as bigInt} from 'big-integer';
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
    constructor(identity: Identity, config: Config) {
        this.identity = identity;
        this.config = config;
    }

    public generateVerifier(): PromiseLike<Verifier> {
        const hashAlgorithm = this.config.getHashAlgorith();
        const primeSize = this.config.getPrimeSize();
        const group = new Group(primeSize);
        const prime = group.getPrime();
        const generator = group.getGenerator();
        const salt = randomSalt();
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
}
