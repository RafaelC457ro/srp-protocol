import {BigInteger} from "big-integer";
export class Crypto {
    public randomSalt(): Buffer {
        const array: Uint8Array = new Uint8Array(32);

        return Buffer.from(crypto.getRandomValues(array));
    }

    public hash(hashAlgorithm: string, buffer: Buffer): PromiseLike<Buffer> {
        return crypto.subtle
            .digest(hashAlgorithm, buffer)
            .then((hashBin: ArrayBuffer) => Buffer.from(hashBin));
    }

    public multiplier(prime: BigInteger, generator: BigInteger): Buffer {
        const primeBuffer: Buffer = this.bigNumberToBuffer(prime);
        const generatorBuffer: Buffer = this.bigNumberToBuffer(generator);

        return Buffer.concat([
            primeBuffer,
            this.zeroLeftPad(primeBuffer.length - 1, generatorBuffer)
        ]);
    }

    public zeroLeftPad(len: number, buffer: Buffer): Buffer {
        if (buffer.length >= len) {
            return buffer;
        }

        const zeroPad: Buffer = new Buffer(len);

        return Buffer.concat([zeroPad, buffer]);
    }

    // I dont totaly undestood this but this guy fix the result
    // https://coolaj86.com/articles/convert-js-bigints-to-typedarrays/
    public bigNumberToBuffer(bn: BigInteger): Buffer {
        let hex: string = bn.toString(16);
        if (hex.length % 2 !== 0) {
            hex = `0${hex}`;
        }

        const len: number = hex.length / 2;
        const u8: Uint8Array = new Uint8Array(len);

        let i: number = 0;
        let j: number = 0;
        while (i < len) {
            u8[i] = parseInt(hex.slice(j, j + 2), 16);
            i += 1;
            j += 2;
        }

        return Buffer.from(u8);
    }
}
