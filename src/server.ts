export class Server {
    constructor() {}
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
}
