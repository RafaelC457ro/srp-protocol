import {Client, Config, Identity, Server} from '../src/index';

describe('srp', () => {
    it('should authenticate', done => {
        const config = new Config(1024, 'SHA-1');
        const identity = new Identity('alice', 'password123');
        const client = new Client(identity, config);

        const registerPromise = client.generateVerifier();
        const clientKeyPairPromise = client.generatekeyPair();

        Promise.all([registerPromise, clientKeyPairPromise])
            .then(([register, clientKeyPair]) => {
                const server = new Server(register.verifier, config);
                return server.generateKeyPair().then(serverKeyPair => {
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
                    .then(proof => {
                        const server = new Server(register.verifier, config);
                        return server.isClientValidProof(
                            proof,
                            serverKeyPair,
                            clientKeyPair.publicKey
                        );
                    });
            })
            .then(isValid => {
                expect(isValid).toBeTruthy();
                done();
            })
            .catch(err => {
                done();
            });
    });
});
