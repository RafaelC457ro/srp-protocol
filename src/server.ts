import {BigInteger, default as bigInt} from 'big-integer';
import {hash, randomSalt} from './crypto';
import {Group} from './groups';
import {Config} from './config';
import {KeyPair} from './keypair';

export class Server {
    private config: Config;
    constructor(config: Config) {
        this.config = config;
    }
    public serverKeyPair(passwordVerifier: string): PromiseLike<KeyPair> {
        const hashAlgorithm = this.config.getHashAlgorith();
        const primeSize = this.config.getPrimeSize();
        const group = new Group(primeSize);
        const prime = group.getPrime();
        const generator = group.getGenerator();
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
}
