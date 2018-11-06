interface Verifier {
    username: string;
    salt: string;
    verifier: string;
}

export class Client {
    constructor() {}

    public generateVerifier(indentity: Identity): PromiseLike<Verifier> {
        const {hashAlgorithm, primeSize} = this.config;
        const {prime, generator} = getGroup(primeSize);
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

    public generatekeyPair(): KeyPair {
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
