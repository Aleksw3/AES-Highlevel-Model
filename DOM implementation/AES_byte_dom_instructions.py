import sys, os
sys.path.append(os.path.dirname(os.path.dirname(__file__))+"/Shared")
from mix_column import xtimeN

from pickletools import uint2
from sbox_dom import SBox


def aes(rs1, rs2, rs3, bs: uint2, is_decrypt: bool, is_middle_round: bool):
    assert(bs <= 3)
    assert(rs1 <= 2**256 - 1 and rs2 <= 2**256 - 1 and rs3 <= 2**256 - 1)

    share1_byte = (rs2 >> ((3-bs)*8) )& 0xFF
    share2_byte = (rs3 >> ((3-bs)*8) )& 0xFF

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

    share1_rotated_tmp = share1_mix if bs == 0 else \
              (share1_mix&0x00FFFFFF) << 8  |  (share1_mix&0xFF000000) >> 24 if bs == 1 else \
              (share1_mix&0x0000FFFF) << 16 |  (share1_mix&0xFFFF0000) >> 16 if bs == 2 else \
              (share1_mix&0x000000FF) << 24 |  (share1_mix&0xFFFFFF00) >> 8  if bs == 3 else -1
    
    share2_rotated_tmp = share2_mix if bs == 0 else \
              (share2_mix&0x00FFFFFF) << 8  |  (share2_mix&0xFF000000) >> 24 if bs == 1 else \
              (share2_mix&0x0000FFFF) << 16 |  (share2_mix&0xFFFF0000) >> 16 if bs == 2 else \
              (share2_mix&0x000000FF) << 24 |  (share2_mix&0xFFFFFF00) >> 8  if bs == 3 else -1
    share1_rotated = ((share1_rotated_tmp&0xFF000000)>>24) | ((share1_rotated_tmp&0x00FF0000)>>8) | ((share1_rotated_tmp&0x0000FF00)<<8) | ((share1_rotated_tmp&0x000000FF)<<24)
    share2_rotated = ((share2_rotated_tmp&0xFF000000)>>24) | ((share2_rotated_tmp&0x00FF0000)>>8) | ((share2_rotated_tmp&0x0000FF00)<<8) | ((share2_rotated_tmp&0x000000FF)<<24)

    assert share1_rotated_tmp != -1 and share2_rotated_tmp != -1

    key_addition = share1_rotated ^ rs1
    result = key_addition ^ share2_rotated

    return result

def aes32dsmi(column_share1, column_share2, key, bs):
    return aes(key, column_share1, column_share2, bs, is_decrypt = True, is_middle_round = True)

def aes32dsi(column_share1, column_share2, key, bs):
    return aes(key, column_share1, column_share2, bs, is_decrypt = True, is_middle_round = False)

def aes32esmi(column_share1, column_share2, key, bs):
    return aes(key, column_share1, column_share2, bs, is_decrypt = False, is_middle_round = True)

def aes32esi(column_share1, column_share2, key, bs):
    return aes(key, column_share1, column_share2, bs, is_decrypt = False, is_middle_round = False)

a = aes(0xAA00AA00, 0xe10000e1^0x20000020, 0x20000020, 3, is_decrypt = False, is_middle_round = True)
print(f"{a:08x}")