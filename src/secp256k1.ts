import {
    hashs,
    getRandomValue,
    powmod,
    calculateModulo,
    tobe256,
    bigintFromBuffer,
} from "./utils";
import {
    N,
    G,
    P,
    A,
    B,
    multiply,
    inv,
    jacobian_multiply,
    jacobian_add,
    from_jacobian,
} from "./matrixOperations";
import { pubkey_to_ethaddr } from "./ecdsa2";


// safe_ord = ord if sys.version_info.major == 2 else lambda x: x if isinstance(x, int) else ord(x)
// returns the Unicode code point for a one-character string
export function safe_ord(x: number | string): number {
    if(typeof x == "string" && x.length > 1) throw new Error("x should be a one-character string or a number");
    if(typeof x == "number") return x;
    else return x.charCodeAt(0);
}

// bytes_to_int = bigintFromBuffer
// si il y a un message a signer, a priori on n'a pas besoin de hashpn et donc de hashsn

// randsn = lambda: randint(1, N - 1)
export function randsn(): bigint { // OK je suppose
    return getRandomValue(1n, N - 1n);
}

// sbmul = lambda s: multiply(G, s)
export function sbmul(s: bigint): [bigint, bigint] { // OK
    return multiply(G, s);
}

// invmulp = lambda x, y: (x * pow(y, P-2, P))
export function invmulp(x: bigint, y: bigint): bigint { // OK
    return (x * powmod(y, P - 2n, P));
}

// invmodn = lambda x: inv(x, N)
export function invmodn(x: bigint): bigint { // OK
    return inv(x, N);
}

// addmodn = lambda x, y: (x + y) % N
export function addmodn(x: bigint, y: bigint): bigint { // OK
    return calculateModulo((x + y), N);
}

// mulmodn = lambda x, y: (x * y) % N
export function mulmodn(x: bigint, y: bigint): bigint { // OK
    return calculateModulo((x * y), N);
}

// submodn = lambda x, y: (x - y) % N
export function submodn(x: bigint, y: bigint): bigint { // OK
    return calculateModulo((x - y), N);
}

// negp = lambda x: (x[0], -x[1])
export function negp(x: [bigint, bigint]): [bigint, bigint] { // OK
    return [x[0], -x[1]];
}

// def hackymul_raw(x, y, scalar, m=0):
// 	"""
// 	Implements the 'hacky multiply' from:
// 	https://ethresear.ch/t/you-can-kinda-abuse-ecrecover-to-do-ecmul-in-secp256k1-today/2384
// 	"""
// 	print(type(x))
// 	print(type(y))
// 	#m = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
// 	v = 28 if y % 2 != 0 else 27
// 	s = mulmodn(scalar, x)
// 	print(s); 
// 	return ecdsa_raw_recover(tobe256(m), (v, x, s))
export function hackymul_raw(x: bigint, y: bigint, scalar: bigint, m: bigint = 0n): [bigint, bigint] { // OK
    let v: bigint = 27n;
    if(calculateModulo(y, 2n) != 0n) v = 28n;
    const s: bigint = mulmodn(scalar, x);
    return ecdsa_raw_recover(tobe256(m), [v, x, s]);
}

// def ecdsa_raw_recover(msghash: bytes, vrs: Tuple[int, int, int]) -> "PlainPoint2D":
//     v, r, s = vrs
//     if not (27 <= v <= 34):
//         raise ValueError("%d must in range 27-31" % v)
//     x = r
//     xcubedaxb = (x * x * x + A * x + B) % P
//     beta = pow(xcubedaxb, (P + 1) // 4, P)
//     y = beta if v % 2 ^ beta % 2 else (P - beta)
//     # If xcubedaxb is not a quadratic residue, then r cannot be the x coord
//     # for a point on the curve, and so the sig is invalid
//     if (xcubedaxb - y * y) % P != 0 or not (r % N) or not (s % N):
//         raise ValueError("sig is invalid, %d cannot be the x coord for point on curve" % r)
//     z = bytes_to_int(msghash)
//     Gz = jacobian_multiply(cast("PlainPoint3D", (Gx, Gy, 1)), (N - z) % N)
//     XY = jacobian_multiply(cast("PlainPoint3D", (x, y, 1)), s)
//     Qr = jacobian_add(Gz, XY)
//     Q = jacobian_multiply(Qr, inv(r, N))
//     Q_jacobian = from_jacobian(Q)

//     return Q_jacobian
export function ecdsa_raw_recover(msghash: Buffer, vrs: [bigint, bigint, bigint]): [bigint, bigint] { // OK
    const v: bigint = vrs[0];
    const r: bigint = vrs[1];
    const s: bigint = vrs[2];
    if(!(27n <= v && v <= 34n)) throw new Error("v must in range 27-31");
    const x: bigint = r;
    const xcubedaxb: bigint = calculateModulo((x * x * x + A * x + B), P);
    const beta: bigint = powmod(xcubedaxb, (P + 1n) / 4n, P);
    let y: bigint = P - beta;
    if(calculateModulo(v, 2n) ^ calculateModulo(beta, 2n)) y = beta;
    if(calculateModulo(xcubedaxb - y * y, P) != 0n || !calculateModulo(r, N) || !calculateModulo(s, N)) throw new Error("sig is invalid, %d cannot be the x coord for point on curve");
    const z: bigint = bigintFromBuffer(msghash);
    const Gz: [bigint, bigint, bigint] = jacobian_multiply([G[0], G[1], 1n], calculateModulo((N - z), N));
    const XY: [bigint, bigint, bigint] = jacobian_multiply([x, y, 1n], s);
    const Qr: [bigint, bigint, bigint] = jacobian_add(Gz, XY);
    const Q: [bigint, bigint, bigint] = jacobian_multiply(Qr, inv(r, N));

    return from_jacobian(Q);
}

// def hackymul(x, y, scalar, m=0):
// 	return pubkey_to_ethaddr(hackymul_raw(x, y, scalar, m))
export function hackymul(x: bigint, y: bigint, scalar: bigint, m: bigint = 0n): Buffer { // 
    return pubkey_to_ethaddr(hackymul_raw(x, y, scalar, m));
}
