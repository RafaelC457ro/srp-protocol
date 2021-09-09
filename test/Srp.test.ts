import {Client, Config, Server} from "../src/index";

describe("Srp", () => {
    it("should authenticate (1024-bits, SHA-1)", (done) => {
        const config = new Config(1024, "SHA-1");
        const client = new Client("alice", "password123", config);

        const registerPromise = client.generateVerifier();
        const clientKeyPairPromise = client.generatekeyPair();

        Promise.all([registerPromise, clientKeyPairPromise])
            .then(([register, clientKeyPair]) => {
                const server = new Server(register.verifier, config);
                return server.generateKeyPair().then((serverKeyPair) => {
                    return {
                        serverKeyPair,
                        register,
                        clientKeyPair
                    };
                });
            })
            .then(({serverKeyPair, register, clientKeyPair}) => {
                return client
                    .proof(clientKeyPair, serverKeyPair.publicKey)
                    .then((proof) => {
                        const server = new Server(register.verifier, config);
                        return server.isClientValidProof(
                            proof,
                            serverKeyPair,
                            clientKeyPair.publicKey
                        );
                    });
            })
            .then((isValid) => {
                expect(isValid).toBeTruthy();
                done();
            })
            .catch((err) => {
                done();
            });
    });

    it("should authenticate (2048-bits, SHA-256)", (done) => {
        const config = new Config(2048, "SHA-256");
        const client = new Client("alice", "password123", config);

        const registerPromise = client.generateVerifier();
        const clientKeyPairPromise = client.generatekeyPair();

        Promise.all([registerPromise, clientKeyPairPromise])
            .then(([register, clientKeyPair]) => {
                const server = new Server(register.verifier, config);
                return server.generateKeyPair().then((serverKeyPair) => {
                    return {
                        serverKeyPair,
                        register,
                        clientKeyPair
                    };
                });
            })
            .then(({serverKeyPair, register, clientKeyPair}) => {
                return client
                    .proof(clientKeyPair, serverKeyPair.publicKey)
                    .then((proof) => {
                        const server = new Server(register.verifier, config);
                        return server.isClientValidProof(
                            proof,
                            serverKeyPair,
                            clientKeyPair.publicKey
                        );
                    });
            })
            .then((isValid) => {
                expect(isValid).toBeTruthy();
                done();
            })
            .catch((err) => {
                done();
            });
    });

    it("should authenticate (8192-bits, SHA-512)", (done) => {
        const config = new Config(8192, "SHA-512");
        const client = new Client("alice", "password123", config);

        const registerPromise = client.generateVerifier();
        const clientKeyPairPromise = client.generatekeyPair();

        Promise.all([registerPromise, clientKeyPairPromise])
            .then(([register, clientKeyPair]) => {
                const server = new Server(register.verifier, config);
                return server.generateKeyPair().then((serverKeyPair) => {
                    return {
                        serverKeyPair,
                        register,
                        clientKeyPair
                    };
                });
            })
            .then(({serverKeyPair, register, clientKeyPair}) => {
                return client
                    .proof(clientKeyPair, serverKeyPair.publicKey)
                    .then((proof) => {
                        const server = new Server(register.verifier, config);
                        return server.isClientValidProof(
                            proof,
                            serverKeyPair,
                            clientKeyPair.publicKey
                        );
                    });
            })
            .then((isValid) => {
                expect(isValid).toBeTruthy();
                done();
            })
            .catch((err) => {
                done();
            });
    });
});
