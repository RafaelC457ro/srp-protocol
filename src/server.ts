import {BigInteger, default as bigInt} from 'big-integer';
import {hash, randomSalt} from './crypto';
import {Group} from './groups';
import {Config} from './config';
import {KeyPair} from './keypair';
import leftPad from 'left-pad';

export class Server {
    private config: Config;
    private passwordVerifier: string;
    constructor(passwordVerifier: string, config: Config) {
        this.config = config;
        this.passwordVerifier = passwordVerifier;
    }

    public generateKeyPair(): PromiseLike<KeyPair> {
        const hashAlgorithm = this.config.getHashAlgorithm();
        const primeSize = this.config.getPrimeSize();
        const group = new Group(primeSize);
        const prime = group.getPrime();
        const generator = group.getGenerator();
        const privateKey = randomSalt();
        const passwordVerifier = bigInt(this.passwordVerifier);
        return hash(
            hashAlgorithm,
            prime.toString() + generator.toString()
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

    public generatePremasterSecret(clientPublicKey: string, keyPair: KeyPair) {
        const hashAlgorithm = this.config.getHashAlgorithm();
        const primeSize = this.config.getPrimeSize();
        const group = new Group(primeSize);
        const prime = group.getPrime();
        const generator = group.getGenerator();
        const primeLenght = group.getPrimeLength();
        const scrambling = hash(
            hashAlgorithm,
            leftPad(clientPublicKey, primeLenght) +
                leftPad(keyPair.public, primeLenght)
        );
    }
}
