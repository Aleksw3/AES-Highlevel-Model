def xtime(byte):
    shifted = (byte << 1) & 0xFF
    return shifted ^ 0x1B if byte & 0x80 else shifted

def xtimeN(byte, n):
    result = 0
    while n:
        if n & 1:
            result ^= byte
        byte = xtime(byte)
        n >>= 1
    return result
