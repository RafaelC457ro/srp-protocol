export function randomSalt(): Buffer {
    // const array: Uint8Array = new Uint8Array(32);
    // const random: Buffer = Buffer.from(crypto.getRandomValues(array));
    return Buffer.from('BEB25379D1A8581EB5A727673A2441EE', 'hex');
}

export function hash(
    hashAlgorithm: string,
    buffer: Buffer
): PromiseLike<Buffer> {
    return crypto.subtle
        .digest(hashAlgorithm, buffer)
        .then(hash => Buffer.from(hash));
}
