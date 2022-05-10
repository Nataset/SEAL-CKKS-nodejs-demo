const express = require('express');
const SEAL = require('node-seal');
const prompt = require('prompt-sync')({ sigint: true });
const port = 3000;

async function main() {
    const app = express();
    const seal = await SEAL();

    app.use(express.json({ limit: '1mb' }));

    app.get('/', (req, res) => {
        // res.json({ Hi: 'Hello World!' });

        const cipher_result = seal.CipherText();
        console.dir(cipher_result);
        res.json({ Hi: 'HELLO WORLD' });
    });

    app.post('/', (req, res) => {
        const size = Buffer.byteLength(JSON.stringify(req.body));
        const mbSize = size / (1024 * 1024);
        console.log('\nGot POST Request, Request body size:', mbSize.toFixed(2), 'MB');
        console.time('Time taken by CKKS');
        const { parmsBase64, pkBase64, dataABase64, dataBBase64 } = req.body;

        // load parms in to context
        const parms = seal.EncryptionParameters(seal.SchemeType.ckks);
        parms.load(parmsBase64);

        // createa context
        const context = seal.Context(parms, false, seal.SecurityLevel.none);

        // load publickey
        const public_key = seal.PublicKey();
        public_key.load(context, pkBase64);

        // load data in cipherText
        const cipher_a = seal.CipherText();
        const cipher_b = seal.CipherText();

        cipher_a.load(context, dataABase64);
        cipher_b.load(context, dataBBase64);

        const plain_z = seal.PlainText();
        const cipher_z = seal.CipherText();

        const ckksEncoder = seal.CKKSEncoder(context);
        const evaluator = seal.Evaluator(context);
        const encryptor = seal.Encryptor(context, public_key);
        ckksEncoder.encode(Float64Array.from([100]), Math.pow(2, 30), plain_z);
        encryptor.encrypt(plain_z, cipher_z);

        const cipher_result = seal.CipherText();
        evaluator.add(cipher_a, cipher_b, cipher_result);
        evaluator.add(cipher_result, cipher_z, cipher_result);

        const cipherResultBase64 = cipher_result.save();

        res.json({ result: cipherResultBase64 });

        console.log('Finish compute response with status code: ', res.statusCode);
        console.timeEnd('Time taken by CKKS');
    });

    app.listen(port, () => {
        console.log(`Server start at port: ${port}`);
    });
}

main();
