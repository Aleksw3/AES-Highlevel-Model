import sys, os
sys.path.append(os.path.dirname(os.path.dirname(__file__))+"/Correctness_tests")
import AES_test_instructions

import random
from AES_byte_dom_instructions import aes32dsi, aes32dsmi, aes32esi, aes32esmi

BYTE0 = 0
BYTE1 = 1
BYTE2 = 2
BYTE3 = 3

def mask(word):
    random_word = random.randint(0, 2**32 - 1)
    return word ^ random_word, random_word

def unmask(shares: tuple):
    return shares[0] ^ shares[1]

def refresh(shares: tuple):
    random_word = random.randint(0, 2**32 - 1)
    return shares[0] ^ random_word, shares[1] ^ random_word

def xor_shares(a: tuple, b: tuple):
    return a[0] ^ b[0], a[1] ^ b[1]

def rotate_word(shares: tuple):
    return tuple((share&0xFFFFFF00) >> 8 | (share&0x000000FF) << 24 for share in shares)

rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]
def KeyScheduler(key, key_length):
    rounds = 10 if key_length == 128 else 12 if key_length == 192 else 14

    number_of_words_in_key = key_length // 32
    key_blocks = []

    for i in range((rounds+1)*4):
        if i < number_of_words_in_key:
            key_blocks.append(mask(key[i]))

        elif i >= number_of_words_in_key and i % number_of_words_in_key == 0:
            tmp_key_i = rotate_word(key_blocks[-1])

            key_blocks.append((0, 0))
            key_blocks[-1] = aes32esi(tmp_key_i, key_blocks[-1], bs = BYTE0)
            key_blocks[-1] = aes32esi(tmp_key_i, key_blocks[-1], bs = BYTE1)
            key_blocks[-1] = aes32esi(tmp_key_i, key_blocks[-1], bs = BYTE2)
            key_blocks[-1] = aes32esi(tmp_key_i, key_blocks[-1], bs = BYTE3)

            key_blocks[-1] = xor_shares(key_blocks[-1], (rcon[(i//number_of_words_in_key) - 1], 0))
            key_blocks[-1] = xor_shares(key_blocks[-1], key_blocks[i - number_of_words_in_key])

        elif i >= number_of_words_in_key and number_of_words_in_key > 6 and i % number_of_words_in_key == 4:
            tmp_key_i = key_blocks[-1]

            key_blocks.append((0, 0))
            key_blocks[-1] = aes32esi(tmp_key_i, key_blocks[-1], bs = BYTE0)
            key_blocks[-1] = aes32esi(tmp_key_i, key_blocks[-1], bs = BYTE1)
            key_blocks[-1] = aes32esi(tmp_key_i, key_blocks[-1], bs = BYTE2)
            key_blocks[-1] = aes32esi(tmp_key_i, key_blocks[-1], bs = BYTE3)
            key_blocks[-1] = xor_shares(key_blocks[-1], key_blocks[i - number_of_words_in_key])

        else:
            key_blocks.append(xor_shares(key_blocks[-1], key_blocks[-number_of_words_in_key]))

    return key_blocks

def InvMixColKey(keys:list, key_length:int):
    result = []
    for i, word in enumerate(keys):
        if i < 4 or i >= len(keys) - 4:
            result.append(word)
        else:
            tmp = (0, 0)
            tmp = aes32esi(word, tmp, bs = BYTE0)
            tmp = aes32esi(word, tmp, bs = BYTE1)
            tmp = aes32esi(word, tmp, bs = BYTE2)
            tmp = aes32esi(word, tmp, bs = BYTE3)

            result.append((0, 0))
            result[-1] = aes32dsmi(tmp, result[-1], bs = BYTE0)
            result[-1] = aes32dsmi(tmp, result[-1], bs = BYTE1)
            result[-1] = aes32dsmi(tmp, result[-1], bs = BYTE2)
            result[-1] = aes32dsmi(tmp, result[-1], bs = BYTE3)

    return result

def encrypt(plaintext, round_keys, key_length):
    rounds = 10 if key_length == 128 else 12 if key_length == 192 else 14
    state = [xor_shares(mask(plaintext[i]), round_keys[i]) for i in range(4)]

    for i in range(rounds - 1):
        state = [refresh(column) for column in state]
        round_key_tmp = [round_keys[(i+1)*4 + 0], round_keys[(i+1)*4 + 1], round_keys[(i+1)*4 + 2], round_keys[(i+1)*4 + 3]]

        round_key_tmp[0] = aes32esmi(state[0], round_key_tmp[0], bs = BYTE0)
        round_key_tmp[0] = aes32esmi(state[1], round_key_tmp[0], bs = BYTE1)
        round_key_tmp[0] = aes32esmi(state[2], round_key_tmp[0], bs = BYTE2)
        round_key_tmp[0] = aes32esmi(state[3], round_key_tmp[0], bs = BYTE3)

        round_key_tmp[1] = aes32esmi(state[1], round_key_tmp[1], bs = BYTE0)
        round_key_tmp[1] = aes32esmi(state[2], round_key_tmp[1], bs = BYTE1)
        round_key_tmp[1] = aes32esmi(state[3], round_key_tmp[1], bs = BYTE2)
        round_key_tmp[1] = aes32esmi(state[0], round_key_tmp[1], bs = BYTE3)

        round_key_tmp[2] = aes32esmi(state[2], round_key_tmp[2], bs = BYTE0)
        round_key_tmp[2] = aes32esmi(state[3], round_key_tmp[2], bs = BYTE1)
        round_key_tmp[2] = aes32esmi(state[0], round_key_tmp[2], bs = BYTE2)
        round_key_tmp[2] = aes32esmi(state[1], round_key_tmp[2], bs = BYTE3)

        round_key_tmp[3] = aes32esmi(state[3], round_key_tmp[3], bs = BYTE0)
        round_key_tmp[3] = aes32esmi(state[0], round_key_tmp[3], bs = BYTE1)
        round_key_tmp[3] = aes32esmi(state[1], round_key_tmp[3], bs = BYTE2)
        round_key_tmp[3] = aes32esmi(state[2], round_key_tmp[3], bs = BYTE3)

        state = round_key_tmp

    state = [refresh(column) for column in state]
    round_key_tmp = [round_keys[rounds*4 + 0], round_keys[rounds*4 + 1], round_keys[rounds*4 + 2], round_keys[rounds*4 + 3]]

    round_key_tmp[0] = aes32esi(state[0], round_key_tmp[0], bs = BYTE0)
    round_key_tmp[0] = aes32esi(state[1], round_key_tmp[0], bs = BYTE1)
    round_key_tmp[0] = aes32esi(state[2], round_key_tmp[0], bs = BYTE2)
    round_key_tmp[0] = aes32esi(state[3], round_key_tmp[0], bs = BYTE3)

    round_key_tmp[1] = aes32esi(state[1], round_key_tmp[1], bs = BYTE0)
    round_key_tmp[1] = aes32esi(state[2], round_key_tmp[1], bs = BYTE1)
    round_key_tmp[1] = aes32esi(state[3], round_key_tmp[1], bs = BYTE2)
    round_key_tmp[1] = aes32esi(state[0], round_key_tmp[1], bs = BYTE3)

    round_key_tmp[2] = aes32esi(state[2], round_key_tmp[2], bs = BYTE0)
    round_key_tmp[2] = aes32esi(state[3], round_key_tmp[2], bs = BYTE1)
    round_key_tmp[2] = aes32esi(state[0], round_key_tmp[2], bs = BYTE2)
    round_key_tmp[2] = aes32esi(state[1], round_key_tmp[2], bs = BYTE3)

    round_key_tmp[3] = aes32esi(state[3], round_key_tmp[3], bs = BYTE0)
    round_key_tmp[3] = aes32esi(state[0], round_key_tmp[3], bs = BYTE1)
    round_key_tmp[3] = aes32esi(state[1], round_key_tmp[3], bs = BYTE2)
    round_key_tmp[3] = aes32esi(state[2], round_key_tmp[3], bs = BYTE3)

    return [unmask(column) for column in round_key_tmp]

def decrypt(ciphertext, round_keys, key_length):
    rounds = 10 if key_length == 128 else 12 if key_length == 192 else 14
    state = [xor_shares(mask(ciphertext[i]), round_keys[rounds*4 + i]) for i in range(4)]

    for i in range(rounds - 1)[::-1]:
        state = [refresh(column) for column in state]
        round_key_tmp = [round_keys[(i+1)*4 + 0], round_keys[(i+1)*4 + 1], round_keys[(i+1)*4 + 2], round_keys[(i+1)*4 + 3]]

        round_key_tmp[0] = aes32dsmi(state[0], round_key_tmp[0], bs = BYTE0)
        round_key_tmp[0] = aes32dsmi(state[3], round_key_tmp[0], bs = BYTE1)
        round_key_tmp[0] = aes32dsmi(state[2], round_key_tmp[0], bs = BYTE2)
        round_key_tmp[0] = aes32dsmi(state[1], round_key_tmp[0], bs = BYTE3)

        round_key_tmp[1] = aes32dsmi(state[1], round_key_tmp[1], bs = BYTE0)
        round_key_tmp[1] = aes32dsmi(state[0], round_key_tmp[1], bs = BYTE1)
        round_key_tmp[1] = aes32dsmi(state[3], round_key_tmp[1], bs = BYTE2)
        round_key_tmp[1] = aes32dsmi(state[2], round_key_tmp[1], bs = BYTE3)

        round_key_tmp[2] = aes32dsmi(state[2], round_key_tmp[2], bs = BYTE0)
        round_key_tmp[2] = aes32dsmi(state[1], round_key_tmp[2], bs = BYTE1)
        round_key_tmp[2] = aes32dsmi(state[0], round_key_tmp[2], bs = BYTE2)
        round_key_tmp[2] = aes32dsmi(state[3], round_key_tmp[2], bs = BYTE3)

        round_key_tmp[3] = aes32dsmi(state[3], round_key_tmp[3], bs = BYTE0)
        round_key_tmp[3] = aes32dsmi(state[2], round_key_tmp[3], bs = BYTE1)
        round_key_tmp[3] = aes32dsmi(state[1], round_key_tmp[3], bs = BYTE2)
        round_key_tmp[3] = aes32dsmi(state[0], round_key_tmp[3], bs = BYTE3)

        state = round_key_tmp

    state = [refresh(column) for column in state]
    round_key_tmp = [round_keys[0], round_keys[1], round_keys[2], round_keys[3]]

    round_key_tmp[0] = aes32dsi(state[0], round_key_tmp[0], bs = BYTE0)
    round_key_tmp[0] = aes32dsi(state[3], round_key_tmp[0], bs = BYTE1)
    round_key_tmp[0] = aes32dsi(state[2], round_key_tmp[0], bs = BYTE2)
    round_key_tmp[0] = aes32dsi(state[1], round_key_tmp[0], bs = BYTE3)

    round_key_tmp[1] = aes32dsi(state[1], round_key_tmp[1], bs = BYTE0)
    round_key_tmp[1] = aes32dsi(state[0], round_key_tmp[1], bs = BYTE1)
    round_key_tmp[1] = aes32dsi(state[3], round_key_tmp[1], bs = BYTE2)
    round_key_tmp[1] = aes32dsi(state[2], round_key_tmp[1], bs = BYTE3)

    round_key_tmp[2] = aes32dsi(state[2], round_key_tmp[2], bs = BYTE0)
    round_key_tmp[2] = aes32dsi(state[1], round_key_tmp[2], bs = BYTE1)
    round_key_tmp[2] = aes32dsi(state[0], round_key_tmp[2], bs = BYTE2)
    round_key_tmp[2] = aes32dsi(state[3], round_key_tmp[2], bs = BYTE3)

    round_key_tmp[3] = aes32dsi(state[3], round_key_tmp[3], bs = BYTE0)
    round_key_tmp[3] = aes32dsi(state[2], round_key_tmp[3], bs = BYTE1)
    round_key_tmp[3] = aes32dsi(state[1], round_key_tmp[3], bs = BYTE2)
    round_key_tmp[3] = aes32dsi(state[0], round_key_tmp[3], bs = BYTE3)

    return [unmask(column) for column in round_key_tmp]



def main():
    column_i = [0x00010203, 0x20656e4f, 0x656e694e, 0x6f775420]
    key      = [0x74616854, 0x796d2073, 0x6e754b20, 0x75462067]
    key_length  = 128
    keys_new    = KeyScheduler(key, key_length)
    cipher      = encrypt(column_i, keys_new, key_length)
    plaintext   = decrypt(cipher, InvMixColKey(keys_new, key_length), key_length)

    print(f"\nIs encryption/decryption correct? {plaintext == column_i}")
    print(f"{plaintext[0]:08x}, {plaintext[1]:08x}, {plaintext[2]:08x}, {plaintext[3]:08x}")
    print(f"{column_i[0]:08x}, {column_i[1]:08x}, {column_i[2]:08x}, {column_i[3]:08x}")


if __name__ == "__main__":
    if AES_test_instructions.test_instructions(can_print=False):
        print("Error in instructions!!")
        exit()
    if AES_test_instructions.test_keyscheduler(can_print=False):
        print("Error in keyscheduler!")
        exit()
    if AES_test_instructions.test_encryption(can_print=False):
        print("Error in encryption!")
        exit()
    if AES_test_instructions.test_decryption(can_print=False):
        print("Error in decryption!")
        exit()

    main()

