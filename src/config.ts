const suportedPrimes: Array<Number> = [
    1024,
    1536,
    2048,
    3072,
    4096,
    6144,
    8192
];

const suportedHashAlgorith: Array<string> = [
    'SHA-1', // (not supported by Microsoft Edge)
    'SHA-256',
    'SHA-384',
    'SHA-512'
];

export class Config {
    private primeSize: number;
    private hashAlgorithm: string;

    constructor(primeSize: number, hashAlgorithm: string) {
        if (!suportedPrimes.includes(primeSize)) {
            throw new Error('Invalid prime size');
        }

        if (!suportedHashAlgorith.includes(hashAlgorithm)) {
            throw new Error('Invalid hashAlgorithm size');
        }

        this.primeSize = primeSize;
        this.hashAlgorithm = hashAlgorithm;
    }

    public getPrimeSize(): number {
        return this.primeSize;
    }

    public getHashAlgorithm(): string {
        return this.hashAlgorithm;
    }
}
