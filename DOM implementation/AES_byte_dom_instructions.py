import sys, os
sys.path.append(os.path.dirname(os.path.dirname(__file__))+"/Shared")
from mix_column import xtimeN

from pickletools import uint2
from sbox_dom import SBox


def rotate_left(word, bs: uint2):
    shift = bs*8
    return ((word << shift) | (word >> (32 - shift))) & 0xFFFFFFFF

def aes(rs1: tuple, rs2: tuple, bs: uint2, is_decrypt: bool, is_middle_round: bool):
    assert(bs <= 3)
    key_share1, key_share2       = rs1
    column_share1, column_share2 = rs2

    share1_byte = (column_share1 >> (bs*8)) & 0xFF
    share2_byte = (column_share2 >> (bs*8)) & 0xFF

    sub_bytes = SBox(share1_byte, share2_byte, inverse = is_decrypt)
    assert(sub_bytes.share1 <= 0xFF and sub_bytes.share2 <= 0xFF)

    share1_mix_b3   = xtimeN(sub_bytes.share1, 0x0b  if is_decrypt else 3)
    share1_mix_b2   = xtimeN(sub_bytes.share1, 0x0d) if is_decrypt else sub_bytes.share1
    share1_mix_b1   = xtimeN(sub_bytes.share1, 0x09) if is_decrypt else sub_bytes.share1
    share1_mix_b0   = xtimeN(sub_bytes.share1, 0x0e  if is_decrypt else 2)
    share1_mixed = share1_mix_b3<<24 | share1_mix_b2 << 16 | share1_mix_b1 << 8 | share1_mix_b0

    share2_mix_b3   = xtimeN(sub_bytes.share2, 0x0b  if is_decrypt else 3)
    share2_mix_b2   = xtimeN(sub_bytes.share2, 0x0d) if is_decrypt else sub_bytes.share2
    share2_mix_b1   = xtimeN(sub_bytes.share2, 0x09) if is_decrypt else sub_bytes.share2
    share2_mix_b0   = xtimeN(sub_bytes.share2, 0x0e  if is_decrypt else 2)
    share2_mixed = share2_mix_b3<<24 | share2_mix_b2 << 16 | share2_mix_b1 << 8 | share2_mix_b0

    share1_mix = share1_mixed if is_middle_round else sub_bytes.share1
    share2_mix = share2_mixed if is_middle_round else sub_bytes.share2

    share1_rotated = rotate_left(share1_mix, bs)
    share2_rotated = rotate_left(share2_mix, bs)

    return key_share1 ^ share1_rotated, key_share2 ^ share2_rotated

def aes32dsmi(column: tuple, key: tuple, bs):
    return aes(key, column, bs, is_decrypt = True, is_middle_round = True)

def aes32dsi(column: tuple, key: tuple, bs):
    return aes(key, column, bs, is_decrypt = True, is_middle_round = False)

def aes32esmi(column: tuple, key: tuple, bs):
    return aes(key, column, bs, is_decrypt = False, is_middle_round = True)

def aes32esi(column: tuple, key: tuple, bs):
    return aes(key, column, bs, is_decrypt = False, is_middle_round = False)
