export function zeroLeftPad(len: number, buffer: Buffer): Buffer {
    const zeroPad: Buffer = new Buffer(len);

    return Buffer.concat([zeroPad, buffer]);
}
