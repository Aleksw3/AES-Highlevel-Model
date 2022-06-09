import sys, os
sys.path.append(os.path.dirname(os.path.dirname(__file__))+"/Shared")
from mix_column import xtimeN

from sbox import s_box, inv_s_box

def printf(a: str, enable:bool = False):
    if enable:
        print(a)

def aes(rs1, rs2: int, bs: int, dec: bool, mid: bool, enable_print:bool = False):
    assert(bs <= 3)
    assert(rs1 <= 2**256 - 1)

    byte = (rs2 >> ((3-bs)*8) )& 0xFF
    printf(f"sel_byte = {byte:x}", enable_print)
    printf(f"bs = {bs}", enable_print)
    
    sub_byte = inv_s_box[byte] if dec else s_box[byte]
    printf(f"sub_byte = {byte:02x} -> {sub_byte:02x}", False)


    mix_b3   = xtimeN(sub_byte, 11  if dec else 3)
    mix_b2   = xtimeN(sub_byte, 13) if dec else sub_byte
    mix_b1   = xtimeN(sub_byte,  9) if dec else sub_byte
    mix_b0   = xtimeN(sub_byte, 14  if dec else 2)

    result_mix = mix_b3<<24 | mix_b2 << 16 | mix_b1 << 8 | mix_b0
    
    result = result_mix if mid else sub_byte
    printf(f"result = {result:08x}", enable_print)

    rotated = result if bs == 0 else \
              (result&0x00FFFFFF) << 8  |  (result&0xFF000000) >> 24 if bs == 1 else \
              (result&0x0000FFFF) << 16 |  (result&0xFFFF0000) >> 16 if bs == 2 else \
              (result&0x000000FF) << 24 |  (result&0xFFFFFF00) >> 8  if bs == 3 else -1

    rot = (rotated & 0xFF000000) >> 24 | (rotated & 0x00FF0000) >> 8 | (rotated & 0x0000FF00) << 8 | (rotated & 0x000000FF) << 24
    rotated = rot
    assert rotated != -1
    printf(f"rotated = {rotated:08x}", enable_print)

    result = rotated^rs1
    printf(f"last result = {result:08x}", enable_print)
    return result

def aes32dsmi(column, key, bs, enable_print = False):
    return aes(key, column, bs, True, True, enable_print)

def aes32dsi(column, key, bs, enable_print = False):
    return aes(key, column, bs, True, False, enable_print)

def aes32esmi(column, key, bs, enable_print = False):
    return aes(key, column, bs, False, True, enable_print)

def aes32esi(column, key, bs, enable_print = False):
    return aes(key, column, bs, False, False, enable_print)
