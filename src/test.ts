import {
    ecdsa_raw_recover,
    hackymul_raw,
    hackymul,

} from "./secp256k1";
import { hashs } from "./utils";
import {
    hacky_schnorr_calc,
    haosring_randkeys,
    convert_hex_to_int_pairs,
} from "./hackyaosring";


// console.log("output: ", hacky_schnorr_calc([12n, 155n], 12n, 199n, 17n))


console.log(convert_hex_to_int_pairs("0x12345,67890abcdef,1234567890a,bcdef12345,67890abcdef1,234567890ab"));