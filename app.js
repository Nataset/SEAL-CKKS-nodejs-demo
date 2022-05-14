const SEAL = require('node-seal');
const prompt = require('prompt-sync')({ sigint: true });

async function main() {
    const seal = await SEAL();

    console.log('SEAL CKKS NodeJS simple DEMO\n');
    const a_value = parseFloat(prompt('Please Enter First value: '));
    const b_value = parseFloat(prompt('Please Enter Second value: '));

    const schemeType = seal.SchemeType.ckks;
    const securityLevel = seal.SecurityLevel.tc128;
    const polyModulusDegree = 4096;
    const bitSizes = [40, 40];

    const encParms = seal.EncryptionParameters(schemeType);

    encParms.setPolyModulusDegree(polyModulusDegree);

    encParms.setCoeffModulus(
        seal.CoeffModulus.Create(polyModulusDegree, Int32Array.from(bitSizes)),
    );
    const context = seal.Context(encParms, false, securityLevel);

    if (!context.parametersSet()) {
        throw new Error(
            'Could not set the parameters in the given context. Please try different encryption parameters.',
        );
    }

    const keyGenerator = seal.KeyGenerator(context);
    const Secret_key_Keypair_A_ = keyGenerator.secretKey();
    const Public_key_Keypair_A_ = keyGenerator.createPublicKey();
    const Relin_key_Keypair_A_ = keyGenerator.createRelinKeys();

    const Plain_A = seal.PlainText();
    const Plain_B = seal.PlainText();

    const Cipher_A = seal.CipherText();
    const Cipher_B = seal.CipherText();
    const evaluator = seal.Evaluator(context);

    const ckksEncoder = seal.CKKSEncoder(context);
    const encryptor = seal.Encryptor(context, Public_key_Keypair_A_);
    const decryptor = seal.Decryptor(context, Secret_key_Keypair_A_);

    ckksEncoder.encode(Float64Array.from([a_value]), Math.pow(2, 30), Plain_A);
    ckksEncoder.encode(Float64Array.from([b_value]), Math.pow(2, 30), Plain_B);

    encryptor.encrypt(Plain_A, Cipher_A);
    encryptor.encrypt(Plain_B, Cipher_B);

    const Cipher_Result = seal.CipherText();
    evaluator.add(Cipher_A, Cipher_B, Cipher_Result);
    evaluator.exponentiate(Cipher_Result, 2, Relin_key_Keypair_A_, Cipher_Result);

    const Plain_Result = seal.PlainText();
    decryptor.decrypt(Cipher_Result, Plain_Result);
    const decoded_Plain_Result = ckksEncoder.decode(Plain_Result);

    console.log('\nTrue Result:', a_value + b_value);
    console.log('Decoded Result:', decoded_Plain_Result[0]);
}

main();
