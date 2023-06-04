import {
    tobe256,
    bigintFromBuffer,
} from "./utils";
import { keccak256 } from "js-sha3";
// def encode_pubkey(pubkey, mode='bin'):
//     if mode == 'bin':
//         return b'\x04' + tobe256(pubkey[0]) + tobe256(pubkey[1])
//     elif mode == 'hex':
//         return b'04' + hexlify(tobe256(pubkey[0])) + hexlify(tobe256(pubkey[1]))
//     elif mode == 'xhex':
//         return hexlify(tobe256(pubkey[0]))
//     elif mode == 'yhex':
//         return hexlify(tobe256(pubkey[1]))
//     elif mode == 'int':
//         return bytes_to_int(pubkey[0]), bytes_to_int(pubkey[1])
//     elif mode == 'hexint':
//         return hexlify(tobe256(pubkey[0])), hexlify(tobe256(pubkey[1]))
//     else:
//         raise Exception("Invalid encoding mode!")
export function encode_pubkey(pubkey: [bigint, bigint], mode: string = "bin"): Buffer { // OK
    if(mode == "bin") {
        return Buffer.concat([Buffer.from([0x04]), tobe256(pubkey[0]), tobe256(pubkey[1])]);
    } else if(mode == "hex") {
        return Buffer.concat([Buffer.from("04", "hex"), tobe256(pubkey[0]), tobe256(pubkey[1])]);
    } else {
        throw new Error("Invalid encoding mode!");
    }
}

// def pack_signature(v, r, s):
// 	"""
// 	This saves a byte by using the last bit of `s` to store `v`
// 	This allows the signature to be packed into two 256bit words
// 	This is possible because `s` is mod `N`, and the highest bit 
// 	doesn't seem to be used...

// 	Having put it through a SAT solver it's 100% possible for this
// 	bit to be set, but in reality it's very unlikely that this
// 	fails, whereas packing it into the `r` value fails 50% of the
// 	time as you'd expect....
// 	"""
// 	assert v == 27 or v == 28
// 	v = (v - 27) << 255
// 	return tobe256(r), tobe256(s | v)
export function pack_signature(v: bigint, r: bigint, s: bigint): [Buffer, Buffer] { // OK mais tjrs 1 element du buffer qui differe entre python et ts
    if(v != 27n && v != 28n) throw new Error("v should be 27 or 28");
    v = (v - BigInt(27)) << BigInt(255);
    return [tobe256(r), tobe256(s | BigInt(v))];
}

// def unpack_signature(r, sv):
// 	sv = bytes_to_int(sv)
// 	if (sv & (1 << 255)):
// 		v = 28
// 		sv = sv ^ (1 << 255)
// 	else:
// 		v = 27
// 	return v, bytes_to_int(r), sv
export function unpack_signature(r: Buffer, sv: Buffer): [bigint, bigint, bigint] { // OK
    let sv_bingint = bigintFromBuffer(sv);
    let v: bigint;
    if(sv_bingint & (1n << 255n)) {
        v = 28n;
        sv_bingint = sv_bingint ^ (1n << 255n);
    }
    else {
        v = 27n;
    }
    return [v, bigintFromBuffer(r), sv_bingint];
}

// def pubkey_to_ethaddr(pubkey):
// 	if isinstance(pubkey, tuple):
// 		assert len(pubkey) == 2
// 		pubkey = encode_pubkey(pubkey, 'bin')
// 	return hexlify(keccak.new(digest_bits=256,data=pubkey[1:]).digest()[12:])
export function pubkey_to_ethaddr(pubkey: [bigint, bigint]): Buffer { // OK
    if(pubkey.length != 2) throw new Error("pubkey should be a tuple of length 2");
    let pubkey_buffer: Buffer = encode_pubkey(pubkey, "bin");
    // remove the fist byte and hash the rest of the public key with keccak256
    // take the last 20 bytes
    // return its hex representation
    const hash = keccak256(pubkey_buffer.slice(1));
    return Buffer.from(hash.slice(24), "hex");
}