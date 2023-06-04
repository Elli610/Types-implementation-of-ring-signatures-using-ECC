import { keccak256 } from "js-sha3";
import {
    getPublicKey,
    generateECDSAKey,
} from "./keyManagement";
import {
    pickRandomPrime,
    getRandomValue,
    multiplyScalarAndPoint,
    bigintFromBuffer,
} from "./utils";

// Base point on secp256k1
const P: [bigint, bigint] = [BigInt("0x" + "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"), BigInt("0x" + "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")]; // https://crypto.stackexchange.com/questions/60420/what-does-the-special-form-of-the-base-point-of-secp256k1-allow

/**
 * hash a message using keccak256
 * 
 * @param msg - the message to hash
 * 
 * @returns the hash of the message
 */
function hash(msg: string): Buffer {
    const hash = keccak256(msg);
    // convert to buffer
    return Buffer.from(hash, "hex");
}

// generate the signers keys
const n = 5;
let U: [bigint, bigint][] = [];
for(let i = 0; i < n; i++) {
    U.push(getPublicKey(generateECDSAKey()));
}
console.log("signers keys: ", U);

// Message to sign
const clearMessage = "hello world";
const m = bigintFromBuffer(hash(clearMessage));

// set the master private key
const x = generateECDSAKey();
// set the master public key
const Ppub = getPublicKey(x);

// generate the a random prime number q
const q = pickRandomPrime();

// // for each key in U:
// for (let i = 0; i < n; i++) {
//     // pick a random r
//     const ri = getRandomValue(0n, q-1n);
//     const Ri = multiplyScalarAndPoint(ri, P);
//     const IDi = i;
//     const ki: bigint = bigintFromBuffer(hash(IDi.toString(16) + Ri[0].toString(16) + Ri[1].toString(16))); 
//     const zi = ri + ki * x;

// }

// add the signer s public key to the list of public keys
U.push(Ppub);

// for each signer: compute ki = H1(IDi, Ri[0])
let k: bigint[] = [];
let l: bigint[] = [];
let c: bigint[] = [];

// ------------------- Signature ------------------- //

// 1
for (let i = 0; i < n; i++) {
    const IDi = i; // pas sur
    const Ri = U[i];
    const ki: bigint = bigintFromBuffer(hash(IDi.toString(16) + Ri[0].toString(16)));
    k.push(ki);
}

// 2
// randomly choose d 
const d = getRandomValue(0n, q-1n);
for (let i = 0; i < n; i++) {
    const IDi = i; // pas sur
    const ci = getRandomValue(0n, q-1n); 
    c.push(ci);
    const PKi = U[i][0];
    const li = bigintFromBuffer(hash(m.toString() + ci.toString() + IDi.toString() + PKi.toString()));
    l.push(li);
}

// 3
const dP: bigint = d * P[0]; // IDK what is dP
let sum = 0n;
for (let i = 0; i < n; i++) {
    if(U[i] != Ppub){
        const Ri = U[i][0]; // Ri = ri * P
        sum += c[i] * (l[i] + Ri + k[i] * Ppub[0]);
    }
    else{
        console.log("sum: ", i);
    }
} 
            
const data: string = m.toString() + U.toString() + dP.toString() + sum.toString();
const h = bigintFromBuffer(hash(data));

// 4
let sumCi: bigint = 0n
for (let i = 0; i < n; i++) {
    if(U[i] != Ppub){
        sumCi += c[i];
    }
    else{
        console.log("sumCi: ", i);
    }
}
const cs = h - sumCi

// 5
const IDs = U.length - 1 ; // signer id
const ts = x; // secret key of the signer
const ls = bigintFromBuffer(hash(m.toString() + cs.toString() + IDs.toString() + Ppub[0].toString()));
const rs = getRandomValue(0n, q-1n); // pas sur du tt
const Rs = multiplyScalarAndPoint(rs, P); // pas sur du tt
const ks = bigintFromBuffer(hash(IDs.toString(16) + Rs[0].toString(16) + Rs[1].toString(16))); 
const zs = rs + ks * x; // IDK what is zs
const y = d - cs * (ls*ts + zs);

// 6
/**
 * The signature to return is (y, c)
 */



// ------------------- Verification ------------------- //
// We need : m, U, y and c 

// 1
const l_verif: bigint[] = [];
for (let i = 0; i < n; i++) {
    l_verif.push(bigintFromBuffer(hash(m.toString() + c[i].toString() + i.toString() + U[i][0].toString())));
}

// 2

// if the equality holds, the signature is valid
let sumCi_verif = 0n;
for (let i = 0; i < n; i++) {
    sumCi_verif += c[i];
}

let verif_sum = y*P[0];
for (let i = 0; i < n; i++) {
    verif_sum += c[i] * (l_verif[i] + U[i][0] + k[i] * Ppub[0]);
}
const data_verif = m.toString() + U.toString() + verif_sum;
const verifHash = bigintFromBuffer(hash(data_verif));


console.log("verifHash: ", verifHash);
console.log("sumCi_verif: ", sumCi_verif);

console.log(verifHash == sumCi_verif);


