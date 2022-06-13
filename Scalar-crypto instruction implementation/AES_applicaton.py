from AES_byte_instructions import aes32dsi, aes32dsmi, aes32esi, aes32esmi

BYTE0 = 0
BYTE1 = 1
BYTE2 = 2
BYTE3 = 3


def InvMixColKey(keys:list, key_length:int):
    result = []
    for i, word in enumerate(keys):
        if i < 4 or i >= len(keys) - 4:
            result.append(word)
        else:
            tmp = 0
            tmp = aes32esi(word, tmp, bs = BYTE0)
            tmp = aes32esi(word, tmp, bs = BYTE1)
            tmp = aes32esi(word, tmp, bs = BYTE2)
            tmp = aes32esi(word, tmp, bs = BYTE3)

            result.append(0)
            result[-1] = aes32dsmi(tmp, result[-1], bs = BYTE0)
            result[-1] = aes32dsmi(tmp, result[-1], bs = BYTE1)
            result[-1] = aes32dsmi(tmp, result[-1], bs = BYTE2)
            result[-1] = aes32dsmi(tmp, result[-1], bs = BYTE3)
    
    return result
    

rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]
def KeyScheduler(key, key_length):
    rounds = 10 if key_length == 128 else 12 if key_length == 192 else 14

    N = key_length // 32
    key_blocks = []
    for i in range((rounds+1)*4):
        if i < N:
            key_blocks.append(key[i])
            
        elif i >= N and i % N == 0:
            tmp_key_i = (key_blocks[-1]&0xFF000000) >> 24 | (key_blocks[-1]&0x00FFFFFF) << 8

            key_blocks.append(0)
            key_blocks[-1] = aes32esi(tmp_key_i, key_blocks[-1], bs = BYTE0)
            key_blocks[-1] = aes32esi(tmp_key_i, key_blocks[-1], bs = BYTE1)
            key_blocks[-1] = aes32esi(tmp_key_i, key_blocks[-1], bs = BYTE2)
            key_blocks[-1] = aes32esi(tmp_key_i, key_blocks[-1], bs = BYTE3)

            key_blocks[-1] = key_blocks[-1] ^ (rcon[(i//N) - 1] << 24)

            key_blocks[-1] = key_blocks[-1] ^ key_blocks[i-N]


        elif i >= N and N > 6 and i % N == 4:
            tmp_key_i = key_blocks[-1]

            key_blocks.append(0)
            key_blocks[-1] = aes32esi(tmp_key_i, key_blocks[-1], bs = BYTE0)
            key_blocks[-1] = aes32esi(tmp_key_i, key_blocks[-1], bs = BYTE1)
            key_blocks[-1] = aes32esi(tmp_key_i, key_blocks[-1], bs = BYTE2)
            key_blocks[-1] = aes32esi(tmp_key_i, key_blocks[-1], bs = BYTE3)
            key_blocks[-1] ^= key_blocks[-N-1]

        else:
            key_blocks.append(0)
            key_blocks[-1] = key_blocks[-2] ^ key_blocks[-N-1]



    return key_blocks

def encrypt(plaintext, round_keys, key_length):
    rounds = 10 if key_length == 128 else 12 if key_length == 192 else 14
    cipher = [0,0,0,0]
    cipher[0] = round_keys[0] ^ plaintext[0]
    cipher[1] = round_keys[1] ^ plaintext[1]
    cipher[2] = round_keys[2] ^ plaintext[2]
    cipher[3] = round_keys[3] ^ plaintext[3]

    enable_instruction_print = False
    for i in range(rounds - 1):
        tmp_key    = [round_keys[(i+1)*4 + 0], round_keys[(i+1)*4 + 1], round_keys[(i+1)*4 + 2], round_keys[(i+1)*4 + 3]]
        cipher_tmp = [cipher[0], cipher[1],cipher[2],cipher[3]]

        tmp_key[0] = aes32esmi(cipher_tmp[0], tmp_key[0], BYTE0, enable_instruction_print)
        tmp_key[0] = aes32esmi(cipher_tmp[1], tmp_key[0], BYTE1, enable_instruction_print)
        tmp_key[0] = aes32esmi(cipher_tmp[2], tmp_key[0], BYTE2, enable_instruction_print)
        cipher[0]  = aes32esmi(cipher_tmp[3], tmp_key[0], BYTE3, enable_instruction_print)

        tmp_key[1] = aes32esmi(cipher_tmp[1], tmp_key[1], BYTE0, enable_instruction_print)
        tmp_key[1] = aes32esmi(cipher_tmp[2], tmp_key[1], BYTE1, enable_instruction_print)
        tmp_key[1] = aes32esmi(cipher_tmp[3], tmp_key[1], BYTE2, enable_instruction_print)
        cipher[1]  = aes32esmi(cipher_tmp[0], tmp_key[1], BYTE3, enable_instruction_print)

        tmp_key[2] = aes32esmi(cipher_tmp[2], tmp_key[2], BYTE0, enable_instruction_print)
        tmp_key[2] = aes32esmi(cipher_tmp[3], tmp_key[2], BYTE1, enable_instruction_print)
        tmp_key[2] = aes32esmi(cipher_tmp[0], tmp_key[2], BYTE2, enable_instruction_print)
        cipher[2]  = aes32esmi(cipher_tmp[1], tmp_key[2], BYTE3, enable_instruction_print)
        
        tmp_key[3] = aes32esmi(cipher_tmp[3], tmp_key[3], BYTE0, enable_instruction_print)
        tmp_key[3] = aes32esmi(cipher_tmp[0], tmp_key[3], BYTE1, enable_instruction_print)
        tmp_key[3] = aes32esmi(cipher_tmp[1], tmp_key[3], BYTE2, enable_instruction_print)
        cipher[3]  = aes32esmi(cipher_tmp[2], tmp_key[3], BYTE3, enable_instruction_print)
        print(f"Encrypted block: {cipher[0] :08x} {cipher[1] :08x} {cipher[2] :08x} {cipher[3] :08x}\n")

    tmp_key    = [round_keys[rounds*4 + 0], round_keys[rounds*4 + 1], round_keys[rounds*4 + 2], round_keys[rounds*4 + 3]]
    cipher_tmp = [cipher[0], cipher[1],cipher[2],cipher[3]]

    tmp_key[0] = aes32esi(cipher_tmp[0], tmp_key[0], BYTE0, enable_instruction_print)
    tmp_key[0] = aes32esi(cipher_tmp[1], tmp_key[0], BYTE1, enable_instruction_print)
    tmp_key[0] = aes32esi(cipher_tmp[2], tmp_key[0], BYTE2, enable_instruction_print)
    cipher[0]  = aes32esi(cipher_tmp[3], tmp_key[0], BYTE3, enable_instruction_print)

    tmp_key[1] = aes32esi(cipher_tmp[1], tmp_key[1], BYTE0, enable_instruction_print)
    tmp_key[1] = aes32esi(cipher_tmp[2], tmp_key[1], BYTE1, enable_instruction_print)
    tmp_key[1] = aes32esi(cipher_tmp[3], tmp_key[1], BYTE2, enable_instruction_print)
    cipher[1]  = aes32esi(cipher_tmp[0], tmp_key[1], BYTE3, enable_instruction_print)

    tmp_key[2] = aes32esi(cipher_tmp[2], tmp_key[2], BYTE0, enable_instruction_print)
    tmp_key[2] = aes32esi(cipher_tmp[3], tmp_key[2], BYTE1, enable_instruction_print)
    tmp_key[2] = aes32esi(cipher_tmp[0], tmp_key[2], BYTE2, enable_instruction_print)
    cipher[2]  = aes32esi(cipher_tmp[1], tmp_key[2], BYTE3, enable_instruction_print)
    
    tmp_key[3] = aes32esi(cipher_tmp[3], tmp_key[3], BYTE0, enable_instruction_print)
    tmp_key[3] = aes32esi(cipher_tmp[0], tmp_key[3], BYTE1, enable_instruction_print)
    tmp_key[3] = aes32esi(cipher_tmp[1], tmp_key[3], BYTE2, enable_instruction_print)
    cipher[3]  = aes32esi(cipher_tmp[2], tmp_key[3], BYTE3, enable_instruction_print)

    return cipher

def decrypt(ciphertext, round_keys, key_length):
    rounds = 10 if key_length == 128 else 12 if key_length == 192 else 14
    cipher = [0,0,0,0]
    cipher[0] = round_keys[rounds*4 + 0] ^ ciphertext[0]
    cipher[1] = round_keys[rounds*4 + 1] ^ ciphertext[1]
    cipher[2] = round_keys[rounds*4 + 2] ^ ciphertext[2]
    cipher[3] = round_keys[rounds*4 + 3] ^ ciphertext[3]

    for i in range(rounds - 1)[::-1]:
        tmp_key    = [round_keys[(i+1)*4 + 0], round_keys[(i+1)*4 + 1], round_keys[(i+1)*4 + 2], round_keys[(i+1)*4 + 3]]
        cipher_tmp = [cipher[0], cipher[1],cipher[2],cipher[3]]

        tmp_key[0] = aes32dsmi(cipher_tmp[0], tmp_key[0], BYTE0)
        tmp_key[0] = aes32dsmi(cipher_tmp[3], tmp_key[0], BYTE1)
        tmp_key[0] = aes32dsmi(cipher_tmp[2], tmp_key[0], BYTE2)
        cipher[0]  = aes32dsmi(cipher_tmp[1], tmp_key[0], BYTE3)

        tmp_key[1] = aes32dsmi(cipher_tmp[1], tmp_key[1], bs = BYTE0)
        tmp_key[1] = aes32dsmi(cipher_tmp[0], tmp_key[1], bs = BYTE1)
        tmp_key[1] = aes32dsmi(cipher_tmp[3], tmp_key[1], bs = BYTE2)
        cipher[1]  = aes32dsmi(cipher_tmp[2], tmp_key[1], bs = BYTE3)

        tmp_key[2] = aes32dsmi(cipher_tmp[2], tmp_key[2], bs = BYTE0)
        tmp_key[2] = aes32dsmi(cipher_tmp[1], tmp_key[2], bs = BYTE1)
        tmp_key[2] = aes32dsmi(cipher_tmp[0], tmp_key[2], bs = BYTE2)
        cipher[2]  = aes32dsmi(cipher_tmp[3], tmp_key[2], bs = BYTE3)
        
        tmp_key[3] = aes32dsmi(cipher_tmp[3], tmp_key[3], bs = BYTE0)
        tmp_key[3] = aes32dsmi(cipher_tmp[2], tmp_key[3], bs = BYTE1)
        tmp_key[3] = aes32dsmi(cipher_tmp[1], tmp_key[3], bs = BYTE2)
        cipher[3]  = aes32dsmi(cipher_tmp[0], tmp_key[3], bs = BYTE3)

    tmp_key    = [round_keys[0], round_keys[1], round_keys[2], round_keys[3]]
    cipher_tmp = [cipher[0], cipher[1],cipher[2],cipher[3]]

    tmp_key[0] = aes32dsi(cipher_tmp[0], tmp_key[0], bs = BYTE0)
    tmp_key[0] = aes32dsi(cipher_tmp[3], tmp_key[0], bs = BYTE1)
    tmp_key[0] = aes32dsi(cipher_tmp[2], tmp_key[0], bs = BYTE2)
    cipher[0]  = aes32dsi(cipher_tmp[1], tmp_key[0], bs = BYTE3)

    tmp_key[1] = aes32dsi(cipher_tmp[1], tmp_key[1], bs = BYTE0)
    tmp_key[1] = aes32dsi(cipher_tmp[0], tmp_key[1], bs = BYTE1)
    tmp_key[1] = aes32dsi(cipher_tmp[3], tmp_key[1], bs = BYTE2)
    cipher[1]  = aes32dsi(cipher_tmp[2], tmp_key[1], bs = BYTE3)

    tmp_key[2] = aes32dsi(cipher_tmp[2], tmp_key[2], bs = BYTE0)
    tmp_key[2] = aes32dsi(cipher_tmp[1], tmp_key[2], bs = BYTE1)
    tmp_key[2] = aes32dsi(cipher_tmp[0], tmp_key[2], bs = BYTE2)
    cipher[2]  = aes32dsi(cipher_tmp[3], tmp_key[2], bs = BYTE3)
    
    tmp_key[3] = aes32dsi(cipher_tmp[3], tmp_key[3], bs = BYTE0) 
    tmp_key[3] = aes32dsi(cipher_tmp[2], tmp_key[3], bs = BYTE1)
    tmp_key[3] = aes32dsi(cipher_tmp[1], tmp_key[3], bs = BYTE2)
    cipher[3]  = aes32dsi(cipher_tmp[0], tmp_key[3], bs = BYTE3)

    return cipher

if __name__ == "__main__":
    column_i = [0x00112233, 0x44556677,0x8899aabb, 0xccddeeff]
    key = [0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f]

    key_length = len(key) * 32
    round_keys    = KeyScheduler(key, key_length)

    print("ENCRYPTION!!\n")
    cipher      = encrypt(column_i, round_keys, key_length)

    print("DECRYPTION!!\n")
    inverse_mix_col_keys    = InvMixColKey(round_keys, key_length)
    plaintext               = decrypt(cipher, inverse_mix_col_keys, key_length)
    
    print(f"Is encryption/decryption correct? {plaintext == column_i}")
