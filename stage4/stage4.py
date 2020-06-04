#!/usr/bin/env python3

import struct
import binascii
import sys
import hexdump

SBOX = [
    9104682, 6995825, 5800092, 16053191, 6481686, 997556, 14309031, 8706308,
    5345487, 15675982, 7813266, 7142373, 16039821, 9276465, 14115802, 444426,
    12259717, 15421308, 8083287, 16094596, 9490388, 8223769, 12272149, 9278804,
    16233579, 13555036, 5077501, 6235350, 6372401, 12813210, 3006346, 10102635,
    13615009, 13137861, 6456538, 12033236, 12759849, 4006121, 15067888, 2803210,
    13407213, 8864802, 10825419, 2330606, 15051626, 14517087, 13738101, 4000399,
    7922999, 13810011, 12033421, 13298788, 2891423, 2340905, 11911800, 783239,
    3661707, 11731152, 1258656, 13680006, 4574202, 7579158, 1048121, 3950795,
    12306950, 987128, 15494449, 12498380, 15652850, 15776520, 8394518, 3917325,
    16013838, 13310925, 2661126, 13352938, 2206984, 14779519, 4158328, 13987053,
    9724941, 7270611, 13859814, 7342305, 8835519, 2579355, 2366955, 6583450,
    4710367, 12150322, 12839686, 1795186, 12318796, 2495566, 4834000, 4993614,
    15797733, 1299445, 1133451, 6109005, 9685896, 7981013, 3145074, 12192430,
    7501786, 8102324, 11474056, 14215222, 11474054, 6188087, 11233398, 16673035,
    5706017, 3681011, 4304873, 5207996, 15756419, 12123990, 7729303, 9467053,
    10123387, 12958141, 4918361, 3658733, 14992295, 9672225, 6216369, 16088331,
    5930420, 6413711, 3962196, 851986, 2086254, 9828551, 3271108, 14098971,
    12505286, 2864552, 7865526, 7971018, 10755456, 2770436, 12784055, 1958885,
    13022208, 14689446, 6720719, 3026408, 6846180, 16106752, 61609, 3881639,
    15086635, 3156490, 4667195, 2488126, 3876565, 6946338, 9547062, 14065991,
    13698571, 8854056, 129400, 3630088, 3143058, 14226445, 11659577, 10351792,
    14765224, 15240937, 1116971, 13957784, 15651152, 13266392, 9642565, 15693202,
    13042677, 3329594, 3198257, 12611819, 3585049, 6288191, 11650668, 8220921,
    3741712, 8184325, 2092339, 16175582, 9736647, 14591653, 10765025, 5556411,
    7179523, 6455355, 12732628, 1329036, 2816775, 16770958, 9026046, 13270576,
    6340751, 877048, 14903297, 14640849, 14219577, 3035850, 15664723, 1676409,
    14625766, 4962987, 36008, 10514394, 13540583, 297348, 5900331, 10710369,
    2005490, 16508708, 2387224, 11882035, 6073357, 13740957, 16611720, 10793156,
    5606049, 1655159, 2143969, 5295659, 9600328, 14099822, 4480563, 3979095,
    2833360, 1028724, 6308632, 10267665, 7138759, 15167918, 219391, 7678522,
    7040121, 10848922, 5544784, 12945158, 9467228, 3532003, 7033488, 3721843,
    4182442, 11066036, 78808, 205024, 7932264, 13067590, 12162038, 13172539
]

def ROR(x, n, bits = 32):
    mask = (2**n) - 1
    mask_bits = x & mask
    return (x >> n) | (mask_bits << (bits - n))
 
def ROL(x, n, bits = 32):
    return ROR(x, bits - n, bits)

def SHLD(x, y, n, bits = 32):
    mask = (2**bits)-1
    return ((x << n) & mask) | (y >> (bits - n))

CST = 0xB7E15162

class Coconut98(object):

    MODE_ENCRYPT = 0
    MODE_DECRYPT = 1

    def __init__(self, key):

        self.key = key

    def gf64_product(self, x, y):
        p = 0 # the product of the multiplication 
        while x and y:
         # if y is odd, then add the corresponding a to p (final product = sum of all x's corresponding to odd y's)
            if (y & 1):
                # since we're in GF(2^m), addition is an XOR
                p = (p ^ x)
         # GF modulo: if x >= 0x8000000000000000L, then it will overflow when shifted left, so reduce 
            if (x & (1<<63)):
                # XOR with the primitive polynomial x^64 + x^11 + x^2 + x + 1 (must be irreducible)
                x = (x << 1) ^ ((1<<64)|0x807)
            else:
                x <<= 1
            y >>= 1
        return p

    def gf64_product_32bits(self, x, y):
        OUT_ROUND_LEFT = 0
        OUT_ROUND_RIGHT = 0

        OUT_S1_LEFT = x >> 32
        OUT_S1_RIGHT = x & 0xFFFFFFFF
        AES_DW7 = y >> 32
        AES_DW8 = y & 0xFFFFFFFF

        # 64 round as the multiplication is performed as a bit by bit addition
        round = 0
        while round < 64:
            test = 0
            if round < 32:
                test = (AES_DW8 & (1 << round))
            else:
                test = AES_DW7 & (1 << (round-32))
            if test != 0:
                ROUND_LEFT = OUT_S1_LEFT   # always init with output of 1st step
                ROUND_RIGHT = OUT_S1_RIGHT # always init with output of 1st step
                if round > 0:
                    if round >= 4:
                        # handle 4 bits by round * 16 round = 32 bits for each half
                        for j in range(0, round >> 2): # between 0 and 15 round
                            tmp1 = SHLD(ROUND_LEFT, ROUND_RIGHT, 1)
                            tmp2 = (ROUND_RIGHT << 1) & 0xffffffff
                            if ROUND_LEFT & 0x80000000 == 0x80000000:
                                tmp2 ^= 0x807

                            tmp3 = SHLD(tmp1, tmp2, 1)
                            tmp4 = (tmp2 << 1) & 0xffffffff
                            if tmp1 & 0x80000000 == 0x80000000:
                                tmp4 ^= 0x807

                            tmp5 = SHLD(tmp3, tmp4, 1)
                            tmp6 = (tmp4 << 1) & 0xffffffff
                            if tmp3 & 0x80000000 == 0x80000000:
                                tmp6 ^= 0x807

                            tmp7 = SHLD(tmp5, tmp6, 1)
                            tmp8 = (tmp6 << 1) & 0xffffffff
                            if tmp5 & 0x80000000 == 0x80000000:
                                tmp8 ^= 0x807

                            ROUND_LEFT = tmp7
                            ROUND_RIGHT = tmp8

                    for j in range(0, round & 3): # between 0 and 3 round
                        tmp1 = SHLD(ROUND_LEFT, ROUND_RIGHT, 1)
                        tmp2 = (ROUND_RIGHT + ROUND_RIGHT) & 0xffffffff
                        if ROUND_LEFT & 0x80000000 == 0x80000000:
                            tmp2 ^= 0x807
                        ROUND_LEFT = tmp1
                        ROUND_RIGHT = tmp2

                # bit by bit addition
                OUT_ROUND_LEFT ^= ROUND_LEFT
                OUT_ROUND_RIGHT ^= ROUND_RIGHT
            round += 1
        return ((OUT_ROUND_LEFT << 32) | (OUT_ROUND_RIGHT))

    def encrypt(self, payload):
        key_tuple = struct.unpack("<IIIIIIII", self.key)
        return self.compute(payload, key_tuple, Coconut98.MODE_ENCRYPT)
    
    def decrypt(self, payload):
        AES_DW1, AES_DW2, AES_DW3, AES_DW4, AES_DW5, AES_DW6, AES_DW7, AES_DW8 = struct.unpack("<IIIIIIII", self.key)
        rev_K1 = AES_DW2 ^ AES_DW4
        rev_K2 = AES_DW1 ^ AES_DW4
        rev_K3 = AES_DW3
        rev_K4 = AES_DW4
        K5K6p = self.gf64_product((AES_DW5 << 32) | (AES_DW6), (AES_DW7 << 32) | (AES_DW8))
        # Hardcoded value for K7K8 invert as libgf2 doesn't support python3
        K7K8p = 0x247f9823bebea5a8 # GF2QuotientRing(0x807 | (1<<64)).invraw((AES_DW7 << 32) | AES_DW8)
        assert(self.gf64_product(K7K8p, (AES_DW7 << 32) | AES_DW8) == 1)
        rev_K5 = K5K6p >> 32
        rev_K6 = K5K6p & 0xFFFFFFFF
        rev_K7 = K7K8p >> 32
        rev_K8 = K7K8p & 0xFFFFFFFF
        rev_key = (rev_K1, rev_K2, rev_K3, rev_K4, rev_K5, rev_K6, rev_K7, rev_K8)
        return self.compute(payload, rev_key, Coconut98.MODE_DECRYPT)


    def compute(self, payload, key_tuple, mode):

        AES_DW1, AES_DW2, AES_DW3, AES_DW4, AES_DW5, AES_DW6, AES_DW7, AES_DW8 = key_tuple

        out_payload = b""

        K1 = AES_DW1
        K2 = AES_DW1 ^ AES_DW3
        K3 = AES_DW1 ^ AES_DW3 ^ AES_DW4
        K4 = AES_DW1 ^ AES_DW4
        K5 = AES_DW2
        K6 = AES_DW2 ^ AES_DW3
        K7 = AES_DW2 ^ AES_DW3 ^ AES_DW4
        K8 = AES_DW2 ^ AES_DW4

        OUT_LEFT = 0  # edi
        OUT_RIGHT = 0 # esi
        i = 0
        while i < len(payload):

            P1, P2 = struct.unpack("<II", payload[i:i+8])
 
            if mode == Coconut98.MODE_ENCRYPT:
                P1 = P1 ^ OUT_LEFT
                P2 = P2 ^ OUT_RIGHT
  
            # Step 1 (4 Round feistel cipher)

            # F1
            step1 = ROL((((P1 ^ K1) + (SBOX[(P1 ^ K1) & 0xFF] << 8)) & 0xFFFFFFFF), 11)
            step2 = P2 ^ ((step1 + (SBOX[(step1 + CST) & 0xFF] << 8) + CST) & 0xFFFFFFFF)
            # F2
            step3 = ROL(((step2 ^ K2) + (SBOX[(step2 ^ K2) & 0xFF] << 8)) & 0xFFFFFFFF, 11)
            step4 = P1 ^ ((step3 + (SBOX[(step3 + CST) & 0xFF] <<8) + CST) & 0xFFFFFFFF)
            # F3
            step5 = ROL(((step4 ^ K3) + (SBOX[(step4 ^ K3) & 0xFF] << 8)) & 0xFFFFFFFF, 11)
            step6 = step2 ^ ((step5 + (SBOX[(step5 + CST) & 0xFF] << 8) + CST) & 0xFFFFFFFF)
            # F4
            step7 = ROL(((K4 ^ step6) + (SBOX[(K4 ^ step6) & 0xFF] << 8)) & 0xFFFFFFFF, 11)
            step8 = step4 ^ ((step7 + (SBOX[(step7+CST) & 0xFF] << 8) + CST) & 0xFFFFFFFF) 

            OUT_S1_LEFT = step8 ^ AES_DW5
            OUT_S1_RIGHT = step6 ^ AES_DW6


            # Step 2 (decoleration module)

            x = (OUT_S1_LEFT << 32) | OUT_S1_RIGHT
            y = (AES_DW7 << 32) | AES_DW8
            z = self.gf64_product(x, y) 
            P1 = z & 0xffffffff
            P2 = z >> 32

            # Step 3 (4 Round feistel cipher)

            # F1
            step1 = ROL(((P1 ^ K5) + (SBOX[(P1 ^ K5) & 0xFF] << 8)) & 0xFFFFFFFF, 11)
            step2 = P2 ^ ((step1 + (SBOX[(step1 + CST) & 0xFF] << 8) + CST) & 0xFFFFFFFF)
            # F2
            step3 = ROL(((step2 ^ K6) + (SBOX[(step2 ^ K6) & 0xFF] << 8)) & 0xFFFFFFFF, 11)
            step4 = P1 ^ ((step3 + (SBOX[(step3 + CST) & 0xFF] <<8) + CST) & 0xFFFFFFFF)
            # F3
            step5 = ROL(((step4 ^ K7) + (SBOX[(step4 ^ K7) & 0xFF] << 8)) & 0xFFFFFFFF, 11)
            step6 = step2 ^ ((step5 + (SBOX[(step5 + CST) & 0xFF] << 8) + CST) & 0xFFFFFFFF)
            # F4
            step7 = ROL(((K8 ^ step6) + (SBOX[(K8 ^ step6) & 0xFF] << 8)) & 0xFFFFFFFF, 11)
            step8 = step4 ^ ((step7 + (SBOX[(step7 + CST) & 0xFF] << 8) + CST) & 0xFFFFFFFF)

            OUT_LEFT = step6
            OUT_RIGHT = step8

            if mode == Coconut98.MODE_DECRYPT:
                if i >= 8:
                    PREV_LEFT, PREV_RIGHT = struct.unpack("<II", payload[i-8:i])
                else:
                    PREV_LEFT = PREV_RIGHT = 0
                OUT_LEFT ^= PREV_LEFT
                OUT_RIGHT ^= PREV_RIGHT
            out_payload += struct.pack("<II", OUT_LEFT, OUT_RIGHT)
            i += 8
        return out_payload

def test():

    payload = b"\x26\x00\x00\x00\x00\x5f\x8d\x13\x8b\x0b\xd6\x01\x00\x70\xfd\xb2"
    encrypted_payload = b"\xA7\x7C\x81\xAA\x49\x00\x60\x35\x47\xB4\xFF\xF3\xB0\x83\x95\xFC"

    coconut_key = struct.pack(">IIIIIIII", 
        0x354da39f, 0xd1532f07, 0xe0fb29d0, 0x1c1418b5, 
        0x7a85e9ba, 0xf363c5ae, 0x421bddef, 0x79fcd292)

    coco = Coconut98(coconut_key)
    cipher=coco.encrypt(payload)
    assert(cipher==encrypted_payload)
    res = coco.decrypt(encrypted_payload)
    assert(res == payload)

if __name__ == '__main__':

    test()

    if len(sys.argv) == 2:
        flow_path = sys.argv[1]
    else:
        flow_path='../../tcpflow/192.168.020.128.01041-192.168.020.001.00443'
    with open(flow_path, 'rb') as f:
        flow = f.read()

    # Key extracted using ollydbg
    coconut_key = struct.pack(">IIIIIIII", 
        0x354da39f, 0xd1532f07, 0xe0fb29d0, 0x1c1418b5, 
        0x7a85e9ba, 0xf363c5ae, 0x421bddef, 0x79fcd292)

    coco = Coconut98(coconut_key)

    i = 0
    while i < len(flow):
        # Decrypt struct _WIN32_FIND_DATAA
        file_header = coco.decrypt(flow[i:i+0x140])
        # hexdump.hexdump(file_header)
        file_size, = struct.unpack("<I", file_header[32:36]) # dnFileSizeLow
        file_name = file_header[44:44+260] # cFileName
        file_name_length = file_name.index(b'\x00')
        file_name = str(file_name[0:file_name_length], 'utf-8')
        print(f'Decrypting file: {file_name}, size = {file_size}')
        if file_size % 8:
            aligned_size = file_size + (8 - (file_size % 8))
        else:
            aligned_size = file_size
        encrypted_file_entry = flow[i:i+0x140+aligned_size]
        file_entry = coco.decrypt(encrypted_file_entry)
        file_payload = file_entry[0x140:]
        with open(f'output/{file_name}', 'wb') as f:
            f.write(file_payload[0:file_size])
        i += 0x140 + aligned_size
