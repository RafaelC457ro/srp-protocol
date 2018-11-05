import {Srp} from '../src/index';

describe('srp', () => {
    it('should return 42', done => {
        const srp = new Srp({hashAlgorithm: 'SHA-1', primeSize: 1024});

        const verifier = srp.generateVerifier({
            username: 'rafael',
            password: '1234'
        });

        verifier
            .then(verifier => {
                //console.log(verifier);
                return srp.serverKeyPair(verifier.verifier);
            })
            .then(keyPair => {
                console.log(keyPair);
                expect('42').toBe('42');
                done();
            });
    });
});
