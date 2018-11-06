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
    hashAlgorithm: string;
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

export class Srp {}
