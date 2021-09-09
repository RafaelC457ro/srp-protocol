import {default as bigInt} from "big-integer";
import {Crypto} from "../src/Crypto";
import {Group} from "../src/Groups";

function hexToBin(hex: String) {
    return Buffer.from(hex.replace(/\s|\n/g, ""), "hex");
}

describe("Crypto", () => {
    it("should leftpad zeros", () => {
        const crypto = new Crypto();
        const buf = crypto.zeroLeftPad(5, Buffer.from([1, 2, 3]));
        const expected = Buffer.from([0, 0, 0, 0, 0, 1, 2, 3]);
        expect(buf).toEqual(expected);
    });

    it("should create a random salt", () => {
        // https://tools.ietf.org/html/rfc5054#appendix-B
        // this simulates the implementation of the browser, but it should also simulate the implementation of the node
        const expected = hexToBin("BEB25379 D1A8581E B5A72767 3A2441EE");
        spyOn(window.crypto, "getRandomValues").and.returnValue(expected);

        const crypto = new Crypto();

        const salt = crypto.randomSalt();

        expect(salt).toEqual(expected);
    });

    it("should generate a multiplayer", (done) => {
        // https://tools.ietf.org/html/rfc5054#appendix-B
        const expected = hexToBin(
            "7556AA04 5AEF2CDD 07ABAF0F 665C3E81 8913186F"
        );

        const crypto = new Crypto();
        const group = new Group(1024);
        const prime = group.getPrime();
        const generator = group.getGenerator();
        const multiplier = crypto.multiplier(prime, generator);

        crypto.hash("SHA-1", multiplier).then((hash) => {
            expect(hash).toEqual(expected);
            done();
        });
    });

    it("shoud convert bigNumber to Buffer", () => {
        const crypto = new Crypto();
        const expected = Buffer.from([2]);
        const buff = crypto.bigNumberToBuffer(bigInt(2));
        expect(buff).toEqual(expected);
    });
});
