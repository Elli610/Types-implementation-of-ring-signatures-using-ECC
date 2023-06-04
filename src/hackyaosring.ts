import {
    hackymul,
    randsn,
    sbmul,
    submodn,
    addmodn,
    mulmodn,
} from "./secp256k1";
import { 
    N,
} from "./matrixOperations";
import {
    bigintFromBuffer,
    bufferFromBigint,
    calculateModulo,
    hashs,
    tobe256,
    getRandomNumber,
} from "./utils";


// def hacky_schnorr_calc(xG, s, e, message):
// 	kG = hackymul(xG[0], xG[1], e, m=(((N - s) % N) * xG[0]) % N)
// 	#print(colored(kG,'red'))
// 	return hashs(xG[0], xG[1], bytes_to_int(unhexlify(kG)), message)
export function hacky_schnorr_calc(xG: [bigint, bigint], s: bigint, e: bigint, message: bigint): bigint { 
    const kG: Buffer = hackymul(xG[0], xG[1], e, calculateModulo((((N - s) % N) * xG[0]), N));

    const x: bigint[] = [xG[0], xG[1], bigintFromBuffer(kG), message];
    const data: Buffer = Buffer.concat(x.map(tobe256));

    return hashs(bigintFromBuffer(data));
/**
 * OK DONC LA J4AI EXACTEMENT LES MEMES PTN D4ENTR2ES DANS LES FONCTIONS DE HASHAGE ET CA SORT DIFFEREMENT ? 
 * 
 * apres vérif, les contenus de "before Hash" sont bien les mêmes mais les outputs de fonctions de hachages sont différentes
 */
}


// def haosring_randkeys(n=4):
// 	skeys = [randsn() for _ in range(0, n)]
	
// 	pkeys = [sbmul(sk) for sk in skeys]
	
// 	i = randint(0, n-1)
// 	return pkeys, (pkeys[i], skeys[i])
export function haosring_randkeys(n: number = 4): [[bigint, bigint][], [[bigint, bigint], bigint]] { // OK
    const skeys: bigint[] = [];
    const pkeys: [bigint, bigint][] = [];
    for(let i = 0; i < n; i++) {
        skeys.push(randsn());
        pkeys.push(sbmul(skeys[i]));
    }
    const i: number = getRandomNumber(1, n - 1); 
    return [pkeys, [pkeys[i], skeys[i]]];
}

// def haosring_sign(pkeys, mypair, tees=None, alpha=None, message=None):
// 	assert len(pkeys) > 0
// 	message = message or hashpn(*pkeys)
// 	mypk, mysk = mypair
// 	myidx = pkeys.index(mypk)

// 	tees = tees or [randsn() for _ in range(0, len(pkeys))]
// 	cees = [0 for _ in range(0, len(pkeys))]
// 	alpha = alpha or randsn()

// 	i = myidx
// 	n = 0
// 	while n < len(pkeys):
// 		idx = i % len(pkeys)
// 		c = alpha if n == 0 else cees[idx-1]
		
// 		cees[idx] = hacky_schnorr_calc(pkeys[idx], tees[idx], c, message)
// 		n += 1
// 		i += 1

// 	# Then close the ring, which proves we know the secret for one ring item
// 	# TODO: split into schnorr_alter
// 	alpha_gap = submodn(alpha, cees[myidx-1])
// 	tees[myidx] = addmodn(tees[myidx], mulmodn(mysk, alpha_gap))
// 	print(pkeys, tees, cees[-1])
// 	return pkeys, tees, cees[-1]
export function haosring_sign(pkeys: [bigint, bigint][], mypair: [[bigint, bigint], bigint], message: bigint) { 
    if(pkeys.length <= 0) throw new Error("pkeys should be a non-empty array");
    const mypk: [bigint, bigint] = mypair[0];
    const mysk: bigint = mypair[1];
    const myidx: number = pkeys.indexOf(mypk);

    const tees: bigint[] = [];
    const cees: bigint[] = [];
    for(let i = 0; i < pkeys.length; i++) {
        tees.push(randsn());
        cees.push(0n);
    }
    const alpha = randsn();

    let i: number = myidx;
    let n: number = 0;
    while(n < pkeys.length) {
        const idx = Number(calculateModulo(BigInt(i), BigInt(pkeys.length)));
        let c = cees[idx - 1];
        if(n == 0) c = alpha;

        cees[idx] = hacky_schnorr_calc(pkeys[idx], tees[idx], c, message);
        n += 1;
        i += 1;
    }

    const alpha_gap: bigint = submodn(alpha, cees[myidx - 1]);
    tees[myidx] = addmodn(tees[myidx], mulmodn(mysk, alpha_gap));
    return [pkeys, tees, cees[cees.length - 1]];
}


// def convert_hex_to_int_pairs(hex_str):
//      # split the input string into a list of hex strings
//         hex_list = hex_str.split(',')

//      # convert each hex string to an integer
//         int_list = [int(hex_val, 16) for hex_val in hex_list]

//         # group the integers into pairs
//         int_pairs = [(int_list[i], int_list[i+1]) for i in range(0, len(int_list), 2)]
//         print(int_pairs)
//         return int_pairs
export function convert_hex_to_int_pairs(hex_str: string): [bigint, bigint][] { // OK
    const hex_list: string[] = hex_str.split(",");
    const int_list: bigint[] = [];
    for(let i = 0; i < hex_list.length; i++) {
        int_list.push(BigInt(parseInt(hex_list[i], 16)));
    }
    const int_pairs: [bigint, bigint][] = [];
    for(let i = 0; i < int_list.length; i += 2) {
        int_pairs.push([int_list[i], int_list[i + 1]]);
    }
    return int_pairs;
}

// def haosring_check(pkeys, tees, seed, message=None):
// 	assert len(pkeys) > 0
// 	assert len(tees) == len(pkeys)
// 	message = message or hashpn(*pkeys)
// 	c = seed
// 	for i, pkey in enumerate(pkeys):
// 		c = hacky_schnorr_calc(pkey, tees[i], c, message)
// 	return c == seed
export function haosring_check(pkeys: [bigint, bigint][], tees: bigint[], seed: bigint, message: bigint): boolean {
    if(pkeys.length <= 0) throw new Error("pkeys should be a non-empty array");
    if(tees.length != pkeys.length) throw new Error("tees should have the same length as pkeys");
    let c: bigint = seed;
    for(let i = 0; i < pkeys.length; i++) {
        c = hacky_schnorr_calc(pkeys[i], tees[i], c, message);
    }
    return c == seed;
}

// def hex_string_to_int_tuple(hex_str):
//     hex_str_list = hex_str.split(',')
//     int_tuple = tuple(int(x, 16) for x in hex_str_list)
//     return int_tuple
export function hex_string_to_int_tuple(hex_str: string): [bigint, bigint] {
    const hex_str_list: string[] = hex_str.split(",");
    const int_tuple: [bigint, bigint] = [BigInt(parseInt(hex_str_list[0], 16)), BigInt(parseInt(hex_str_list[1], 16))];
    return int_tuple;
}

// def convertHexPubKeyToInt(_x,_y):
// 	x = int(_x,16)
// 	y = int(_y,16)
// 	return x,y
export function convertHexPubKeyToInt(_x: string, _y: string): [bigint, bigint] {
    const x: bigint = BigInt(parseInt(_x, 16));
    const y: bigint = BigInt(parseInt(_y, 16));
    return [x, y];
}