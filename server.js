const express = require('express');
const SEAL = require('node-seal');
const prompt = require('prompt-sync')({ sigint: true });
const port = 3000;

async function main() {
    const app = express();
    const seal = await SEAL();

    app.use(express.json({ limit: '5mb' }));

    app.get('/', (req, res) => {
        res.json({ Hi: 'HELLO WORLD' });
    });

    app.post('/', (req, res, next) => {
        console.log('Reuest Type:', req.method);
        next();
    });

    app.post('/:scheme', (req, res) => {
        const size = Buffer.byteLength(JSON.stringify(req.body));
        const mbSize = size / (1024 * 1024);
        const reqScheme = req.params.scheme;
        console.log(`\nGot POST Request, Request body size:`, mbSize.toFixed(2), 'MB');
        console.log(`|------ Scheme Type: ${reqScheme.toUpperCase()} ------|`);
        console.time(`Time taken by ${reqScheme.toUpperCase()}`);
        const { parmsBase64, pkBase64, dataABase64, dataBBase64, rlkBase64 } = req.body;

        // load parms in to context
        const parms = seal.EncryptionParameters();
        parms.load(parmsBase64);

        // createa context
        const context = seal.Context(parms, false, seal.SecurityLevel.none);

        // load publickey
        const public_key = seal.PublicKey();
        const relin_key = seal.RelinKeys();
        public_key.load(context, pkBase64);
        relin_key.load(context, rlkBase64);

        // load data in cipherText
        const cipher_a = seal.CipherText();
        const cipher_b = seal.CipherText();

        cipher_a.load(context, dataABase64);
        cipher_b.load(context, dataBBase64);

        const plain_c = seal.PlainText();
        const cipher_c = seal.CipherText();

        const encryptor = seal.Encryptor(context, public_key);
        const evaluator = seal.Evaluator(context);
        let cipherResultBase64 = null;

        switch (reqScheme) {
            case 'ckks':
                const ckksEncoder = seal.CKKSEncoder(context);
                ckksEncoder.encode(Float64Array.from([100]), Math.pow(2, 30), plain_c);
                break;
            case 'bfv':
            case 'bgv':
                const batchEncoder = seal.BatchEncoder(context);
                batchEncoder.encode(Int32Array.from([100]), plain_c);
                break;
        }
        encryptor.encrypt(plain_c, cipher_c);

        const cipher_result = seal.CipherText();
        evaluator.add(cipher_a, cipher_b, cipher_result);
        evaluator.add(cipher_result, cipher_c, cipher_result);

        cipherResultBase64 = cipher_result.save();
        res.json({ result: cipherResultBase64 });
        console.log('Finish compute response with status code: ', res.statusCode);
        console.timeEnd(`Time taken by ${reqScheme.toUpperCase()}`);
    });

    app.listen(3000, () => {
        console.log(`listening on port 3000`);
    });
}

main();
