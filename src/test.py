from utils import *
from ecdsa2 import *
from secp256k1 import *
import math
from py_ecc.secp256k1.secp256k1 import add, multiply, inv, N, P, G, ecdsa_raw_recover, jacobian_add, jacobian_double, to_jacobian, jacobian_multiply
from hackyaosring import *


# print("output: ", hacky_schnorr_calc([12, 155], 12, 199, 17))

print(convert_hex_to_int_pairs("0x12345,67890abcdef,1234567890a,bcdef12345,67890abcdef1,234567890ab"))