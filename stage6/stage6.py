#!/usr/bin/env python3
from Crypto.Hash import keccak
import struct
import sys

def ROR(x, n, bits = 32):
    mask = (2**n) - 1
    mask_bits = x & mask
    return (x >> n) | (mask_bits << (bits - n))
 
def ROL(x, n, bits = 32):
    return ROR(x, bits - n, bits)

def binary_to_int(bit_array):
    res = 0
    for i in range(0, len(bit_array)):
        res |= (bit_array[i] << i) 
    return res

def highest_power_of_two(x):
    i = 0
    while x & 1 == 0:
        x >>= 1
        i += 1
    return i

mask_256 = 2**256-1
mask_128 = 2**128-1
mask_64 = 2**64-1
mask_32 = 2**32-1
mask_8 = 2**8-1

class AlaideCipher(object):

    def __init__(self, memory_file_path):

        self.contract_memory = {}
        self.seed = 0
        with open(memory_file_path, 'r') as f:
            for line in f:
                if line.startswith('Memory slot'):
                    tokens = line.split(' ')
                    if len(tokens) == 5:
                        self.contract_memory[int(tokens[2], 16)] = int(tokens[4],16)
        self.output = None
        self.invert_func_constructor()
        self.xor_hash = self.build_xor_hash()
        self.xor_prng = self.build_xor_qword_table()
        self.bitflip_table = self.build_bitflip_table()
        self.swap_index = self.build_swap_index_table()

    def build_xor_qword_table(self):
        t = [0xc9c5032724e9488a, 0xdf5e047488d9b088, 0x573d11fbd9edccb8, 0xf0df4f17f6b9a0f2, 
            0xe72c7a5d270e8d9e, 0xdb35ef5c16d97f14, 0x46f788162474e74d, 0xd1a4f97c583b681a, 
            0xdd89f3fbab633d07, 0xbbf44beb08a09f3d, 0x8510019582d0238d, 0x12e0aac60d84eab2, 
            0xea9cd675a7bd39b5, 0x8ade103b3ad91825, 0x87ae0734f03c1b16, 0x70b177b255029440, 
            0xda9d7ba675914fb0, 0xfbf4344a28020d3d, 0xf0a3f936583a27c4, 0x90bd50e3f8795ff4, 
            0x5def899da5ecb6db, 0x9180628960520b84, 0x194abcd56426e72c, 0x4ab2805d0cf267eb, 
            0xb2b7f3627b203384, 0x90506d9e8256e5fa, 0xaa9fba88519fa0ce, 0x454356ba804c583e, 
            0x98241768c093d034, 0x8607259ac40eca39, 0xd891c496729af0d6, 0x97bbd6588154582e]
        return t

    def build_bitflip_table(self):
        bit_table = []
        for i in range(0,32):
            qword_mask = 0
            for j in range(0,8):
                bit_value = (i & (1 << j)) >> j
                bit_xor = bit_value << 7 # used to xor one byte
                qword_mask |= (bit_xor) << (j * 8)
            bit_table.append(qword_mask)
        return bit_table


    def build_xor_hash(self):
        input_hash = self.seed ^ 0x4d30442053515541
        hashes = []
        for i in range(0, 32):
            input_hash = self.compute_hash(input_hash)
            hashes.append(input_hash)
        return hashes

    def compute_hash(self, h_value):
        for j in range(0, 64):
            output = (h_value & 0x5245205230305421)
            for j2 in range(1, 64):
                output = output ^ ((h_value & 0x5245205230305421) >> j2)
            h_value = (((output << 63) | (((h_value)) >> 1)) & (0xffffffffffffffff))
        return h_value
    
    def build_xor_key(self, contract_byte):
        key = 0
        for j in range(0,8):
            key |= (contract_byte) << (j << 3)
            contract_byte = ROL(contract_byte, 1, 8)
        return key

    def build_swap_index_table(self):
        input = [i for i in range(0,32)]
        prng_swap = [0x19,0x13,0x7,0x14,0x11,0x12,0x6,0x15,0x4,0xa,0xd,0x13,0xe,0xf,0xb,0x0,0xa,0x3,0x9,0xb,0x5,0x2,0x2,0x7,0x0,0x2,0x1,0x2,0x2,0x0,0x1]
        assert(len(prng_swap) == 31)
        assert(len(input) == 32)
        i = 31
        while i > 0:
            tmp = input[i]
            input[i] = input[prng_swap[31-i]]
            input[prng_swap[31-i]] = tmp
            i -= 1
        return input

    def invert_func_constructor(self):
        xor_mod_squa = 0x4d30442053515541 # 'M0D SQUA'
        re_root = 0x5245205230305421 # 'RE R00T!'
        s = self.contract_memory[0]
        self.seed = ((s >> 32) & mask_64) ^ xor_mod_squa # only keep this one as it is not modified
        assert(((s >> 96) & mask_64) == re_root)

    def get_key(self, i):
        hash_input = b"\x00" * (0x20-4) + struct.pack(">I", i) + b"\x00"*(0x20-1) + b"\x01"             
        key = int(keccak.new(digest_bits=256).update(hash_input).hexdigest(), 16)
        return key

    def solve_quadratic_equation_mod_n(self, a, b, c, n):
        self.output = [0]*n
        self._solve_quadratic_equation_mod_n(a, b, c, n, 0)
        return binary_to_int(self.output)

    def _solve_quadratic_equation_mod_n(self, a, b, c, n, i):
        if i == 64:
            return
        if highest_power_of_two(c) > 0:
            self.output[i] = 0
            self._solve_quadratic_equation_mod_n((2*a), b, c // 2, n-1, i+1)
        else:
            self.output[i] = 1
            self._solve_quadratic_equation_mod_n((2 * a), (2*a + b), ((a//2) + (b//2) + (c//2) + 1), n-1, i+1)

    def decrypyt(self):
        output = {}
        for i in range(0, 32):
            memory_slot = self.contract_memory[self.get_key(i)]
            A = 0x854e9fb4699ed8f22fd89ebe3f17f7f6 # 128 bit
            B = 0xd677105721b51a080288a52f7aa48517 # 128 bit
            C = -memory_slot
            X = self.solve_quadratic_equation_mod_n(A, B, C, 64)
            X = X ^ self.xor_hash[i]
            X = X ^ self.xor_prng[i]
            pos = self.swap_index[i]
            X = X ^ self.bitflip_table[pos]
            for contract_byte in range(0,256):
                xor_key = self.build_xor_key(contract_byte)
                final = X ^ xor_key
                # Test if value is encoded on 7 bits
                if final & 0x7f7f7f7f7f7f7f7f == final:
                    final_str = struct.pack("<Q", final)
                    output[pos] = final
        final_str = b''
        for key in sorted(output):
            final_str += struct.pack("<Q", output[key])
        print(final_str)

if __name__ == '__main__':
    if len(sys.argv) == 2:
        contract_path = sys.argv[1]
    else:
        contract_path = '../contract_memory.txt'
    alaide = AlaideCipher(contract_path)
    alaide.decrypyt()
