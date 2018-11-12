import {Client, Config, Identity, Server} from '../src/index';

describe('srp', () => {
    it('should return 42', done => {
        const config = new Config(1024, 'SHA-1');
        const identity = new Identity('alice', 'password123');
        const client = new Client(identity, config);

        const verifierPromise = client.generateVerifier();
        const clientKeyPairPromise = client.generatekeyPair();

        Promise.all([verifierPromise, clientKeyPairPromise])
            .then(([verifier, clientKeyPair]) => {
                const server = new Server(verifier.verifier, config);
                return server.generateKeyPair().then(serverKeyPair => {
                    return {
                        serverKeyPair,
                        verifier,
                        clientKeyPair
                    };
                });
            })
            .then(({serverKeyPair, verifier, clientKeyPair}) => {
                return client
                    .proof(clientKeyPair, serverKeyPair.public)
                    .then(proof => {
                        const server = new Server(verifier.verifier, config);
                        return server.isClientValidProof(
                            proof,
                            serverKeyPair,
                            clientKeyPair.public
                        );
                    });
            })
            .then(isValid => {
                expect(isValid).toBeTruthy();
                done();
            })
            .catch(err => {
                console.log(err);
                done();
            });
    });
});
