import {Client} from "../src/Client";
import {Config} from "../src/Config";
import {KeyPair} from "../src/Keypair";

function hexToBin(hex: String) {
    return Buffer.from(hex.replace(/\s|\n/g, ""), "hex");
}

describe("Client", () => {
    it("should generate client verifier", (done) => {
        const expectVerifier = hexToBin(`
            7E273DE8 696FFC4F 4E337D05 B4B375BE B0DDE156 9E8FA00A 9886D812
            9BADA1F1 822223CA 1A605B53 0E379BA4 729FDC59 F105B478 7E5186F5
            C671085A 1447B52A 48CF1970 B4FB6F84 00BBF4CE BFBB1681 52E08AB5
            EA53D15C 1AFF87B2 B9DA6E04 E058AD51 CC72BFC9 033B564E 26480D78
            E955A5E2 9E7AB245 DB2BE315 E2099AFB
        `);

        // mocking random salt
        const salt = hexToBin("BEB25379 D1A8581E B5A72767 3A2441EE");
        spyOn(window.crypto, "getRandomValues").and.returnValue(salt);

        const config = new Config(1024, "SHA-1");
        const client = new Client("alice", "password123", config);

        client.generateVerifier().then((register) => {
            expect(register.verifier).toEqual(expectVerifier.toString("hex"));
            done();
        });
    });

    it("should generate x", (done) => {
        const expectedX = hexToBin(
            "94B7555A ABE9127C C58CCF49 93DB6CF8 4D16C124"
        );

        // mocking random salt
        const salt = hexToBin("BEB25379 D1A8581E B5A72767 3A2441EE");
        spyOn(window.crypto, "getRandomValues").and.returnValue(salt);

        const config = new Config(1024, "SHA-1");
        const client = new Client("alice", "password123", config);

        client.calcX().then((x) => {
            expect(x.toString("hex")).toEqual(expectedX.toString("hex"));
            done();
        });
    });

    it("should gererate client key pairs", (done) => {
        const expectedPrivateKey = hexToBin(
            "60975527 035CF2AD 1989806F 0407210B C81EDC04 E2762A56 AFD529DD DA2D4393"
        );

        const expectedPublicKey = hexToBin(`
            61D5E490 F6F1B795 47B0704C 436F523D D0E560F0 C64115BB 72557EC4
            4352E890 3211C046 92272D8B 2D1A5358 A2CF1B6E 0BFCF99F 921530EC
            8E393561 79EAE45E 42BA92AE ACED8251 71E1E8B9 AF6D9C03 E1327F44
            BE087EF0 6530E69F 66615261 EEF54073 CA11CF58 58F0EDFD FE15EFEA
            B349EF5D 76988A36 72FAC47B 0769447B
        `);

        // mocking random private key
        spyOn(window.crypto, "getRandomValues").and.returnValue(
            expectedPrivateKey
        );

        const config = new Config(1024, "SHA-1");
        const client = new Client("alice", "password123", config);

        client.generatekeyPair().then((clientKeyPair: KeyPair) => {
            expect(clientKeyPair.privateKey).toEqual(
                expectedPrivateKey.toString("hex")
            );

            expect(clientKeyPair.publicKey).toEqual(
                expectedPublicKey.toString("hex")
            );
            done();
        });
    });

    it("should gererate u", (done) => {
        const expectedtU = "CE38B959 3487DA98 554ED47D 70A7AE5F 462EF019"
            .replace(/\s|\n/g, "")
            .toLocaleLowerCase();

        const A = `
            61D5E490 F6F1B795 47B0704C 436F523D D0E560F0 C64115BB 72557EC4
            4352E890 3211C046 92272D8B 2D1A5358 A2CF1B6E 0BFCF99F 921530EC
            8E393561 79EAE45E 42BA92AE ACED8251 71E1E8B9 AF6D9C03 E1327F44
            BE087EF0 6530E69F 66615261 EEF54073 CA11CF58 58F0EDFD FE15EFEA
            B349EF5D 76988A36 72FAC47B 0769447B
        `
            .replace(/\s|\n/g, "")
            .toLocaleLowerCase();

        const B = `
            BD0C6151 2C692C0C B6D041FA 01BB152D 4916A1E7 7AF46AE1 05393011
            BAF38964 DC46A067 0DD125B9 5A981652 236F99D9 B681CBF8 7837EC99
            6C6DA044 53728610 D0C6DDB5 8B318885 D7D82C7F 8DEB75CE 7BD4FBAA
            37089E6F 9C6059F3 88838E7A 00030B33 1EB76840 910440B1 B27AAEAE
            EB4012B7 D7665238 A8E3FB00 4B117B58
        `
            .replace(/\s|\n/g, "")
            .toLocaleLowerCase();

        const config = new Config(1024, "SHA-1");
        const client = new Client("alice", "password123", config);

        client.calcU(A, B).then((U: Buffer) => {
            expect(U.toString("hex")).toEqual(expectedtU);
            done();
        });
    });

    it("should gererate premaster secret", (done) => {
        const expectedPremasterSecret = `
            B0DC82BA BCF30674 AE450C02 87745E79 90A3381F 63B387AA F271A10D
            233861E3 59B48220 F7C4693C 9AE12B0A 6F67809F 0876E2D0 13800D6C
            41BB59B6 D5979B5C 00A172B4 A2A5903A 0BDCAF8A 709585EB 2AFAFA8F
            3499B200 210DCC1F 10EB3394 3CD67FC8 8A2F39A4 BE5BEC4E C0A3212D
            C346D7E4 74B29EDE 8A469FFE CA686E5A
        `
            .replace(/\s|\n/g, "")
            .toLocaleLowerCase();

        const a = "60975527 035CF2AD 1989806F 0407210B C81EDC04 E2762A56 AFD529DD DA2D4393"
            .replace(/\s|\n/g, "")
            .toLocaleLowerCase();

        const A = `
            61D5E490 F6F1B795 47B0704C 436F523D D0E560F0 C64115BB 72557EC4
            4352E890 3211C046 92272D8B 2D1A5358 A2CF1B6E 0BFCF99F 921530EC
            8E393561 79EAE45E 42BA92AE ACED8251 71E1E8B9 AF6D9C03 E1327F44
            BE087EF0 6530E69F 66615261 EEF54073 CA11CF58 58F0EDFD FE15EFEA
            B349EF5D 76988A36 72FAC47B 0769447B
        `
            .replace(/\s|\n/g, "")
            .toLocaleLowerCase();

        const B = `
            BD0C6151 2C692C0C B6D041FA 01BB152D 4916A1E7 7AF46AE1 05393011
            BAF38964 DC46A067 0DD125B9 5A981652 236F99D9 B681CBF8 7837EC99
            6C6DA044 53728610 D0C6DDB5 8B318885 D7D82C7F 8DEB75CE 7BD4FBAA
            37089E6F 9C6059F3 88838E7A 00030B33 1EB76840 910440B1 B27AAEAE
            EB4012B7 D7665238 A8E3FB00 4B117B58
        `
            .replace(/\s|\n/g, "")
            .toLocaleLowerCase();

        // mocking random private key
        spyOn(window.crypto, "getRandomValues").and.returnValue(
            hexToBin("BEB25379 D1A8581E B5A72767 3A2441EE")
        );

        const config = new Config(1024, "SHA-1");
        const client = new Client("alice", "password123", config);

        client
            .generatePreMasterSecret(
                {
                    privateKey: a,
                    publicKey: A
                },
                B
            )
            .then((premasterKey: string) => {
                expect(premasterKey).toEqual(expectedPremasterSecret);
                done();
            });
    });
});
