import { 
    randomBytes,
    createDiffieHellman,
    createPrivateKey,
   } from "crypto";

// picks an initialization (or “glue”) value v uniformly at random from {0, 1}^b
// b is the number of bits
export function pickRandomV(b: number = 256): Buffer {
    // b should be a multiple of 8
    if(b % 8 != 0) throw new Error("b should be a multiple of 8");
    return randomBytes(b / 8);
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

export function pickRandomPrime(): bigint {
    const prime = createDiffieHellman(512); // 512 or 1024 ?
    return bigintFromBuffer(prime.getPrime());
}

export function multiplyScalarAndPoint (scalar: bigint, point: [bigint, bigint]): [bigint, bigint] {
    return [scalar * point[0], scalar * point[1]];
}
  
export function addPoints (point1: [bigint, bigint], point2: [bigint, bigint]): [bigint, bigint] {
    return [point1[0] + point2[0], point1[1] + point2[1]];
}

export function bigintFromBuffer(buffer: Buffer): bigint {
    return BigInt("0x" + buffer.toString("hex"));
}
