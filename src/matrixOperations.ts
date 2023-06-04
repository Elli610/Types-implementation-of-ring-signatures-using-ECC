import { calculateModulo } from "./utils";

export const P: bigint = 2n**256n - 2n**32n - 977n;
export const N: bigint = 115792089237316195423570985008687907852837564279074904382605163141518161494337n;
export const A: bigint = 0n;
export const B: bigint = 7n;
export const Gx: bigint = 55066263022277343669578718895168534326250603453777594175500187360389116729240n;
export const Gy: bigint = 32670510020758816978083085130507043184471273380659243275938904335757337482424n;
export const G: [bigint, bigint] = [Gx, Gy];

export function multiply(a: [bigint, bigint], n: bigint): [bigint, bigint] { // OK
    // console.log("to_jacobian(a): ", to_jacobian(a));
    // console.log("jacobian_multiply(to_jacobian(a), n): ", jacobian_multiply(to_jacobian(a), n)); // pb ici
    return from_jacobian(jacobian_multiply(to_jacobian(a), n));
}

export function to_jacobian(p: [bigint, bigint]): [bigint, bigint, bigint] {
    return [p[0], p[1], 1n];
}

export function jacobian_multiply(a: [bigint, bigint, bigint], n: bigint): [bigint, bigint, bigint] { // OK
    if(a[1] == 0n || n == 0n) {
        return [0n, 0n, 1n];
    }
    if(n == 1n) {
        return a;
    }
    if(n < 0n || n >= N) {
        return jacobian_multiply(a, calculateModulo(n, N));
    }
    if(calculateModulo(n, 2n) == 0n) {
        return jacobian_double(jacobian_multiply(a, n / 2n));
    }
    if(calculateModulo(n, 2n) == 1n) {
        return jacobian_add(jacobian_double(jacobian_multiply(a, (n / 2n))), a);
    }
    throw new Error("Unexpected error in jacobian_multiply");
}

export function jacobian_double(p: [bigint, bigint, bigint], ): [bigint, bigint, bigint] {  // OK
    if(!p[1]) return [0n, 0n, 0n];
    const ysq: bigint = calculateModulo((p[1] ** 2n), P);
    const S: bigint = calculateModulo((4n * p[0] * ysq), P);
    const M: bigint = calculateModulo((3n * (p[0] ** 2n) + A * (p[2] ** 4n)), P);
    const nx: bigint = calculateModulo((M ** 2n - 2n * S), P);
    const ny: bigint = calculateModulo((M * (S - nx)) - (8n * ysq ** 2n), P); // l'habituel % P ne donnait pas le bon résultat
    const nz: bigint = calculateModulo((2n * p[1] * p[2]), P);
    return [nx, ny, nz];
}

export function jacobian_add(p: [bigint, bigint, bigint], q: [bigint, bigint, bigint]): [bigint, bigint, bigint] {  // OK
    if(!p[1]) return q;
    if(!q[1]) return p;
    const U1: bigint = calculateModulo((p[0] * (q[2] ** 2n)), P);
    const U2: bigint = calculateModulo((q[0] * (p[2] ** 2n)), P);
    const S1: bigint = calculateModulo((p[1] * (q[2] ** 3n)), P);
    const S2: bigint = calculateModulo((q[1] * (p[2] ** 3n)), P);
    if(U1 == U2) {
        if(S1 != S2) {
            console.log("iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii");
            return [0n, 0n, 1n];
        }
        console.log("jjjjjjjjjjjjjjjjjjjjjjjjjjjjj");
        return jacobian_double(p);
    }
    const H: bigint = U2 - U1;
    const R: bigint = S2 - S1;
    const H2: bigint = calculateModulo((H * H), P);
    const H3: bigint = calculateModulo((H * H2), P);
    const U1H2: bigint = calculateModulo((U1 * H2), P);
    const nx: bigint = calculateModulo((R ** 2n - H3 - 2n * U1H2), P);
    const ny: bigint = calculateModulo((R * (U1H2 - nx) - S1 * H3), P);
    const nz: bigint = calculateModulo((H * p[2] * q[2]), P);
    return [nx, ny, nz];
}

export function from_jacobian(p: [bigint, bigint, bigint]): [bigint, bigint] {  // OK
    const z = inv(p[2], P);
    return [calculateModulo((p[0] * (z**2n)), P), calculateModulo((p[1] * (z**3n)), P)];
}

export function inv(a: bigint, n: bigint): bigint { // OK
    if(a == 0n) return 0n;
    let lm = 1n;
    let hm = 0n;
    let low = calculateModulo(a, n);
    let high = n;
    while(low > 1n) {
        const r = high / low;
        const nm = hm - lm * r;
        const new_ = high - low * r;
        hm = lm;
        lm = nm;
        high = low;
        low = new_;
    }
    return calculateModulo(lm, n);
}
