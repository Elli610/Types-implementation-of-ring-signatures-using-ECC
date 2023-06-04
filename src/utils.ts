import { keccak256 } from "js-sha3";
import {
    randomBytes,
} from "crypto";

// bytes_to_int = lambda x: reduce(lambda o, b: (o << 8) + safe_ord(b), [0] + list(x))
export function bigintFromBuffer(buffer: Buffer): bigint { // OK
    return BigInt("0x" + buffer.toString("hex"));
}

export function bufferFromBigint(bigint: bigint): Buffer { // OK
    const hex = bigint.toString(16);
    return Buffer.from(hex, "hex");
}

function randomBytesFromRange(range: bigint): Buffer {
    const rangeInB = range.toString(16).length / 2;
    const randomB = randomBytes(rangeInB);
    const randomBigInt = bigintFromBuffer(randomB);
    if(randomBigInt > range) {
        return randomBytesFromRange(range);
    }
    return randomB;
}

export function getRandomValue(min: bigint, max: bigint): bigint {
    const range = max - min;
    const randomBytes = randomBytesFromRange(range);
    return min + bigintFromBuffer(randomBytes);
}

export function getRandomNumber(min: number, max: number): number {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

// def packl(lnum):
//     if lnum == 0:
//         return b'\0'
//     s = hex(lnum)[2:].rstrip('L')
//     if len(s) & 1:
//         s = '0' + s
//     return binascii.unhexlify(s)
export function packl(lnum: bigint): Buffer { // OK
    if(lnum == 0n) return Buffer.from([0]);
    const s = lnum.toString(16);
    if(s.length % 2 == 1) return Buffer.from("0" + s, "hex");
    return Buffer.from(s, "hex");
}

// zpad = lambda x, l: b'\x00' * max(0, l - len(x)) + x
export function zpad(x: Buffer, l: number): Buffer { // python donne : b'\x00\x00\x00\x00\x00\x00I\x96\x02\xd2' et ts: <Buffer 00 00 00 00 00 00 49 96 02 d2> pour zpad(packl(1234567890n), 10)
    const zeros = Buffer.alloc(Math.max(0, l - x.length));
    return Buffer.concat([zeros, x]);
}

// tobe256 = lambda v: zpad(int_to_big_endian(v), 32)
export function tobe256(v: bigint): Buffer { // python donne: b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00I\x96\x02\xd2' et ts: <Buffer 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 49 96 02 d2> pour tobe256(1234567890n)
    return zpad(packl(v), 32);
}

// def hashs(*x):
//     data = b''.join(map(tobe256, x))
//     return bytes_to_int(keccak.new(digest_bits=256,data=data).digest())
export function hashs(msg: bigint): bigint { // OK
    const data = tobe256(msg);
    console.log("before Hash: ", bigintFromBuffer(data));
    const hash = keccak256(data);
    return bigintFromBuffer(Buffer.from(hash, "hex"));
}

// randb256 = lambda: urandom(32)
export function randb256(): Buffer { 
    return randomBytes(32);
}

// bit_clear = lambda n, b: n ^ (1<<(b-1)) if n & 1<<(b-1) else n
export function bit_clear(n: bigint, b: number): bigint { // OK mais si b = 0, pyhton throw mais pas ts
    if(n & (1n << BigInt(b - 1))) return n ^ (1n << BigInt(b - 1));
    return n;
}

// bit_set = lambda n, b: n | (1<<(b-1))
export function bit_set(n: bigint, b: number): bigint { // OK
    return n | (1n << BigInt(b - 1));
}

// bit_test = lambda n, b: 0 != (n & (1<<(b-1)))
export function bit_test(n: bigint, b: number): boolean { // OK
    return 0n != (n & (1n << BigInt(b - 1)));
}

// equivalent de math.log(n, 2) en python 
export function ilog2(n: bigint) {  // OK
    // n is a positive non-zero BigInt
    const C1 = BigInt(1)
    const C2 = BigInt(2)
    for(var count=0n; n>C1; count++)  n = n/C2
    return count
 } // example ilog2(16n)==4

// def powmod(a,b,n):
//     c = 0
//     f = 1
//     k = int(math.log(b, 2))
//     while k >= 0:
//         c *= 2
//         f = (f*f)%n
//         if b & (1 << k):
//             c += 1
//             f = (f*a) % n
//         k -= 1
//     return f
export function powmod(a: bigint, b: bigint, n: bigint): bigint { // OK
    let c: bigint = 0n;
    let f: bigint = 1n;
    let k: bigint = ilog2(b);
    while(k >= 0n) {
        c *= 2n;
        f = (f * f) % n;
        if(b & (1n << k)) {
            c += 1n;
            f = (f * a) % n;
        }
        k -= 1n;
    }
    return f;
}

export function calculateModulo(n: bigint, P: bigint): bigint { 
    const result = n % P;
    return result >= 0n ? result : result + P;
  }
