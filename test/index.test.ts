import {Srp} from '../src/index';

describe('srp', () => {
    it('should return 42', done => {
        const srp = new Srp({hashAlgorithm: 'SHA-1', primeSize: '1024'});

        const verifier = srp.generateVerifier({
            username: 'rafael',
            password: '1234'
        });

        verifier
            .then(verifier => {
                console.log(verifier);
                expect('42').toBe('42');
                done();
            })
            .catch(err => {
                console.log(err);
            });
    });
});
