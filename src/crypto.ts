import {default as bigInt} from 'big-integer';

export function randomSalt(): string {
    const array = new Uint8Array(32);
    const random = Buffer.from(crypto.getRandomValues(array)).toString('hex');
    return bigInt(random, 16).toString();
}

export function hash(hashAlgorithm: string, text: string): PromiseLike<String> {
    const buffer = new TextEncoder().encode(text);
    return crypto.subtle
        .digest(hashAlgorithm, buffer)
        .then(hash => Buffer.from(hash).toString('hex'));
}
