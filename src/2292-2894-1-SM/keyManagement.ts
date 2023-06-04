import * as elliptic from "elliptic";
// get its public key
export function getPublicKey(privateKey: bigint): [bigint, bigint] {
    // convert private key to buffer
    const privateKeyBuffer = Buffer.from(privateKey.toString(16), "hex");
    const ec = new elliptic.ec("secp256k1");
    const key = ec.keyFromPrivate(privateKeyBuffer);
    const pubPoint = key.getPublic();
    const x = pubPoint.getX();
    const y = pubPoint.getY();
    // convert the x and y coordinates to bigint
    const xBigInt = BigInt("0x" + x.toString("hex"));
    const yBigInt = BigInt("0x" + y.toString("hex"));
    return [xBigInt, yBigInt];

}

// generate a random private ECDSA key using secp256k1
export function generateECDSAKey(): bigint {
    const ec = new elliptic.ec('secp256k1');
    const keyPair = ec.genKeyPair();
    
    const privateKey = keyPair.getPrivate('hex');
    
    return BigInt("0x" + privateKey);
  };