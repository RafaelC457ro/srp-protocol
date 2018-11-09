import {BigInteger, default as bigInt} from 'big-integer';
import leftPad from 'left-pad';
import {hash, randomSalt} from './crypto';
import {Group} from './groups';
import {Config} from './config';
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

    public generatePremasterSecret(
        clientPublicKeyString: string,
        keyPair: KeyPair
    ): PromiseLike<string> {
        const hashAlgorithm = this.config.getHashAlgorithm();
        const primeSize = this.config.getPrimeSize();
        const group = new Group(primeSize);
        const prime = group.getPrime();
        const primeLenght = group.getPrimeLength();
        const passwordVerifier = this.passwordVerifier;
        const clientPublicKey = bigInt(clientPublicKeyString);
        return hash(
            hashAlgorithm,
            leftPad(clientPublicKeyString, primeLenght) +
                leftPad(keyPair.public, primeLenght)
        ).then((scramblingHash: string) => {
            const scrambling = bigInt(scramblingHash, 16);
            return clientPublicKey
                .multiply(passwordVerifier.modPow(scrambling, prime))
                .modPow(bigInt(keyPair.private), prime)
                .toString();
        });
    }
}
