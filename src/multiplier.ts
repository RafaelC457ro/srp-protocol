import {BigInteger} from 'big-integer';
import {zeroLeftPad} from './zero-left-pad';

export function multiplier(prime: BigInteger, generator: BigInteger): Buffer {
    const primeBuffer: Buffer = new Buffer(prime.toString(16), 'hex');
    const generatorBuffer: Buffer = Buffer.from(generator.toArray(16).value);

    return Buffer.concat([
        primeBuffer,
        zeroLeftPad(primeBuffer.length - 1, generatorBuffer)
    ]);
}
