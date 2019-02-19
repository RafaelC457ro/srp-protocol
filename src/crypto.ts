export function randomSalt(): Buffer {
    const array: Uint8Array = new Uint8Array(32);

    return Buffer.from(crypto.getRandomValues(array));
}

export function hash(
    hashAlgorithm: string,
    buffer: Buffer
): PromiseLike<Buffer> {
    return crypto.subtle
        .digest(hashAlgorithm, buffer)
        .then((hashBin: ArrayBuffer) => Buffer.from(hashBin));
}
