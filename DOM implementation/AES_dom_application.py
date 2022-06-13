import sys, os
sys.path.append(os.path.dirname(os.path.dirname(__file__))+"/Correctness_tests")
import AES_test_instructions

import random
from AES_byte_dom_instructions import aes32dsi, aes32dsmi, aes32esi, aes32esmi

BYTE0 = 0
BYTE1 = 1
BYTE2 = 2
BYTE3 = 3

rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]
def KeyScheduler(key, key_length):
    rounds = 10 if key_length == 128 else 12 if key_length == 192 else 14

    number_of_words_in_key = key_length // 32
    key_blocks = []
    
    for i in range((rounds+1)*4):
        if i < number_of_words_in_key:
            key_blocks.append(key[i])
            
        elif i >= number_of_words_in_key and i % number_of_words_in_key == 0:
            random_word = random.randint(0, 2**32 - 1)
            tmp_key_i = (key_blocks[-1]&0xFF000000) >> 24 | (key_blocks[-1]&0x00FFFFFF) << 8

            share1 = tmp_key_i ^ random_word
            share2 = random_word

            key_blocks.append(0)
            key_blocks[-1] = aes32esi(share1, share2, key_blocks[-1], bs = BYTE0)
            key_blocks[-1] = aes32esi(share1, share2, key_blocks[-1], bs = BYTE1)
            key_blocks[-1] = aes32esi(share1, share2, key_blocks[-1], bs = BYTE2)
            key_blocks[-1] = aes32esi(share1, share2, key_blocks[-1], bs = BYTE3)

            key_blocks[-1] = key_blocks[-1] ^ (rcon[(i//number_of_words_in_key) - 1] << 24)
            key_blocks[-1] = key_blocks[-1] ^ key_blocks[i - number_of_words_in_key]

        elif i >= number_of_words_in_key and number_of_words_in_key > 6 and i % number_of_words_in_key == 4:
            random_word = random.randint(0, 2**32 - 1)
            share1 = key_blocks[-1] ^ random_word
            share2 = random_word
            key_blocks.append(0)
            key_blocks[-1] = aes32esi(share1, share2, key_blocks[-1], bs = BYTE0)
            key_blocks[-1] = aes32esi(share1, share2, key_blocks[-1], bs = BYTE1)
            key_blocks[-1] = aes32esi(share1, share2, key_blocks[-1], bs = BYTE2)
            key_blocks[-1] = aes32esi(share1, share2, key_blocks[-1], bs = BYTE3)

        else:
            key_blocks.append(key_blocks[-1]^ key_blocks[-number_of_words_in_key])

    return key_blocks

def create_shares(share1: list):
    random_values = [random.randint(0, 2**(31)-1) for _ in range(4)]

    share2 = [0,0,0,0]

    share1[0]^= random_values[0]
    share1[1]^= random_values[1]
    share1[2]^= random_values[2]
    share1[3]^= random_values[3]

    share2[0] = random_values[0]
    share2[1] = random_values[1]
    share2[2] = random_values[2]
    share2[3] = random_values[3]  

    return share1, share2

def encrypt(plaintext, round_keys, key_length):
    rounds = 10 if key_length == 128 else 12 if key_length == 192 else 14
    share1 = [0,0,0,0]
    share1[0] = plaintext[0] ^ round_keys[0]
    share1[1] = plaintext[1] ^ round_keys[1]
    share1[2] = plaintext[2] ^ round_keys[2]
    share1[3] = plaintext[3] ^ round_keys[3]

    share1, share2 = create_shares(share1)

    for i in range(rounds - 1):
        if i != 0: 
            create_shares(share1)      
      
        round_key_tmp = [round_keys[(i+1)*4 + 0], round_keys[(i+1)*4 + 1], round_keys[(i+1)*4 + 2], round_keys[(i+1)*4 + 3]]
        share1_tmp    = [share1[0], share1[1],share1[2],share1[3]]
        share2_tmp    = [share2[0], share2[1],share2[2],share2[3]]

        round_key_tmp[0] = aes32esmi(share1_tmp[0], share2_tmp[0], round_key_tmp[0], bs = BYTE0)
        round_key_tmp[0] = aes32esmi(share1_tmp[1], share2_tmp[1], round_key_tmp[0], bs = BYTE1)
        round_key_tmp[0] = aes32esmi(share1_tmp[2], share2_tmp[2], round_key_tmp[0], bs = BYTE2)
        share1[0]        = aes32esmi(share1_tmp[3], share2_tmp[3], round_key_tmp[0], bs = BYTE3)

        round_key_tmp[1] = aes32esmi(share1_tmp[1], share2_tmp[1], round_key_tmp[1], bs = BYTE0)
        round_key_tmp[1] = aes32esmi(share1_tmp[2], share2_tmp[2], round_key_tmp[1], bs = BYTE1)
        round_key_tmp[1] = aes32esmi(share1_tmp[3], share2_tmp[3], round_key_tmp[1], bs = BYTE2)
        share1[1]        = aes32esmi(share1_tmp[0], share2_tmp[0], round_key_tmp[1], bs = BYTE3)

        round_key_tmp[2] = aes32esmi(share1_tmp[2], share2_tmp[2], round_key_tmp[2], bs = BYTE0)
        round_key_tmp[2] = aes32esmi(share1_tmp[3], share2_tmp[3], round_key_tmp[2], bs = BYTE1)
        round_key_tmp[2] = aes32esmi(share1_tmp[0], share2_tmp[0], round_key_tmp[2], bs = BYTE2)
        share1[2]        = aes32esmi(share1_tmp[1], share2_tmp[1], round_key_tmp[2], bs = BYTE3)
        
        round_key_tmp[3] = aes32esmi(share1_tmp[3], share2_tmp[3], round_key_tmp[3], bs = BYTE0)
        round_key_tmp[3] = aes32esmi(share1_tmp[0], share2_tmp[0], round_key_tmp[3], bs = BYTE1)
        round_key_tmp[3] = aes32esmi(share1_tmp[1], share2_tmp[1], round_key_tmp[3], bs = BYTE2)
        share1[3]        = aes32esmi(share1_tmp[2], share2_tmp[2], round_key_tmp[3], bs = BYTE3)
    
    share1, share2 = create_shares(share1)      

    round_key_tmp = [round_keys[rounds*4 + 0], round_keys[rounds*4 + 1], round_keys[rounds*4 + 2], round_keys[rounds*4 + 3]]
    share1_tmp    = [share1[0], share1[1],share1[2],share1[3]]
    share2_tmp    = [share2[0], share2[1],share2[2],share2[3]]
    
    round_key_tmp[0] = aes32esi(share1_tmp[0], share2_tmp[0], round_key_tmp[0], bs = BYTE0)
    round_key_tmp[0] = aes32esi(share1_tmp[1], share2_tmp[1], round_key_tmp[0], bs = BYTE1)
    round_key_tmp[0] = aes32esi(share1_tmp[2], share2_tmp[2], round_key_tmp[0], bs = BYTE2)
    share1[0]        = aes32esi(share1_tmp[3], share2_tmp[3], round_key_tmp[0], bs = BYTE3)

    round_key_tmp[1] = aes32esi(share1_tmp[1], share2_tmp[1], round_key_tmp[1], bs = BYTE0)
    round_key_tmp[1] = aes32esi(share1_tmp[2], share2_tmp[2], round_key_tmp[1], bs = BYTE1)
    round_key_tmp[1] = aes32esi(share1_tmp[3], share2_tmp[3], round_key_tmp[1], bs = BYTE2)
    share1[1]        = aes32esi(share1_tmp[0], share2_tmp[0], round_key_tmp[1], bs = BYTE3)

    round_key_tmp[2] = aes32esi(share1_tmp[2], share2_tmp[2], round_key_tmp[2], bs = BYTE0)
    round_key_tmp[2] = aes32esi(share1_tmp[3], share2_tmp[3], round_key_tmp[2], bs = BYTE1)
    round_key_tmp[2] = aes32esi(share1_tmp[0], share2_tmp[0], round_key_tmp[2], bs = BYTE2)
    share1[2]        = aes32esi(share1_tmp[1], share2_tmp[1], round_key_tmp[2], bs = BYTE3)
    
    round_key_tmp[3] = aes32esi(share1_tmp[3], share2_tmp[3], round_key_tmp[3], bs = BYTE0)
    round_key_tmp[3] = aes32esi(share1_tmp[0], share2_tmp[0], round_key_tmp[3], bs = BYTE1)
    round_key_tmp[3] = aes32esi(share1_tmp[1], share2_tmp[1], round_key_tmp[3], bs = BYTE2)
    share1[3]        = aes32esi(share1_tmp[2], share2_tmp[2], round_key_tmp[3], bs = BYTE3)

    return share1

def decrypt(ciphertext, round_keys, key_length):
    rounds = 10 if key_length == 128 else 12 if key_length == 192 else 14

    share1 = [0,0,0,0]
    share2 = [0,0,0,0]

    share1[0] = round_keys[rounds*4 + 0] ^ ciphertext[0]
    share1[1] = round_keys[rounds*4 + 1] ^ ciphertext[1]
    share1[2] = round_keys[rounds*4 + 2] ^ ciphertext[2]
    share1[3] = round_keys[rounds*4 + 3] ^ ciphertext[3]

    for i in range(rounds - 1)[::-1]:
        random_values = [random.randint(0, 2**(31)-1) for _ in range(4)]

        share1[0]^= random_values[0]
        share1[1]^= random_values[1]
        share1[2]^= random_values[2]
        share1[3]^= random_values[3]

        share2[0] = random_values[0]
        share2[1] = random_values[1]
        share2[2] = random_values[2]
        share2[3] = random_values[3] 

        round_key_tmp = [round_keys[(i+1)*4 + 0], round_keys[(i+1)*4 + 1], round_keys[(i+1)*4 + 2], round_keys[(i+1)*4 + 3]]
        share1_tmp    = [share1[0], share1[1], share1[2], share1[3]]
        share2_tmp    = [share2[0], share2[1], share2[2], share2[3]]

        round_key_tmp[0] = aes32dsmi(share1_tmp[0], share2_tmp[0], round_key_tmp[0], bs = BYTE0)
        round_key_tmp[0] = aes32dsmi(share1_tmp[3], share2_tmp[3], round_key_tmp[0], bs = BYTE1)
        round_key_tmp[0] = aes32dsmi(share1_tmp[2], share2_tmp[2], round_key_tmp[0], bs = BYTE2)
        share1[0]        = aes32dsmi(share1_tmp[1], share2_tmp[1], round_key_tmp[0], bs = BYTE3)

        round_key_tmp[1] = aes32dsmi(share1_tmp[1], share2_tmp[1], round_key_tmp[1], bs = BYTE0)
        round_key_tmp[1] = aes32dsmi(share1_tmp[0], share2_tmp[0], round_key_tmp[1], bs = BYTE1)
        round_key_tmp[1] = aes32dsmi(share1_tmp[3], share2_tmp[3], round_key_tmp[1], bs = BYTE2)
        share1[1]        = aes32dsmi(share1_tmp[2], share2_tmp[2], round_key_tmp[1], bs = BYTE3)

        round_key_tmp[2] = aes32dsmi(share1_tmp[2], share2_tmp[2], round_key_tmp[2], bs = BYTE0)
        round_key_tmp[2] = aes32dsmi(share1_tmp[1], share2_tmp[1], round_key_tmp[2], bs = BYTE1)
        round_key_tmp[2] = aes32dsmi(share1_tmp[0], share2_tmp[0], round_key_tmp[2], bs = BYTE2)
        share1[2]        = aes32dsmi(share1_tmp[3], share2_tmp[3], round_key_tmp[2], bs = BYTE3)
        
        round_key_tmp[3] = aes32dsmi(share1_tmp[3], share2_tmp[3], round_key_tmp[3], bs = BYTE0)
        round_key_tmp[3] = aes32dsmi(share1_tmp[2], share2_tmp[2], round_key_tmp[3], bs = BYTE1)
        round_key_tmp[3] = aes32dsmi(share1_tmp[1], share2_tmp[1], round_key_tmp[3], bs = BYTE2)
        share1[3]        = aes32dsmi(share1_tmp[0], share2_tmp[0], round_key_tmp[3], bs = BYTE3)

    random_values = [random.randint(0, 2**(31)-1) for _ in range(4)]
    share1[0]^= random_values[0]
    share1[1]^= random_values[1]
    share1[2]^= random_values[2]
    share1[3]^= random_values[3]

    share2[0] = random_values[0]
    share2[1] = random_values[1]
    share2[2] = random_values[2]
    share2[3] = random_values[3] 

    round_key_tmp = [round_keys[0], round_keys[1], round_keys[2], round_keys[3]]
    share1_tmp    = [share1[0], share1[1], share1[2], share1[3]]
    share2_tmp    = [share2[0], share2[1], share2[2], share2[3]]

    round_key_tmp[0] = aes32dsi(share1_tmp[0], share2_tmp[0], round_key_tmp[0], bs = BYTE0)
    round_key_tmp[0] = aes32dsi(share1_tmp[3], share2_tmp[3], round_key_tmp[0], bs = BYTE1)
    round_key_tmp[0] = aes32dsi(share1_tmp[2], share2_tmp[2], round_key_tmp[0], bs = BYTE2)
    share1[0]        = aes32dsi(share1_tmp[1], share2_tmp[1], round_key_tmp[0], bs = BYTE3)

    round_key_tmp[1] = aes32dsi(share1_tmp[1], share2_tmp[1], round_key_tmp[1], bs = BYTE0)
    round_key_tmp[1] = aes32dsi(share1_tmp[0], share2_tmp[0], round_key_tmp[1], bs = BYTE1)
    round_key_tmp[1] = aes32dsi(share1_tmp[3], share2_tmp[3], round_key_tmp[1], bs = BYTE2)
    share1[1]        = aes32dsi(share1_tmp[2], share2_tmp[2], round_key_tmp[1], bs = BYTE3)

    round_key_tmp[2] = aes32dsi(share1_tmp[2], share2_tmp[2], round_key_tmp[2], bs = BYTE0)
    round_key_tmp[2] = aes32dsi(share1_tmp[1], share2_tmp[1], round_key_tmp[2], bs = BYTE1)
    round_key_tmp[2] = aes32dsi(share1_tmp[0], share2_tmp[0], round_key_tmp[2], bs = BYTE2)
    share1[2]        = aes32dsi(share1_tmp[3], share2_tmp[3], round_key_tmp[2], bs = BYTE3)
    
    round_key_tmp[3] = aes32dsi(share1_tmp[3], share2_tmp[3], round_key_tmp[3], bs = BYTE0)
    round_key_tmp[3] = aes32dsi(share1_tmp[2], share2_tmp[2], round_key_tmp[3], bs = BYTE1)
    round_key_tmp[3] = aes32dsi(share1_tmp[1], share2_tmp[1], round_key_tmp[3], bs = BYTE2)
    share1[3]        = aes32dsi(share1_tmp[0], share2_tmp[0], round_key_tmp[3], bs = BYTE3)

    return share1



def main():
    column_i = [0x00010203, 0x20656e4f, 0x656e694e, 0x6f775420]
    key      = [0x74616854, 0x796d2073, 0x6e754b20, 0x75462067]
    key_length  = 128
    keys_new    = KeyScheduler(key, key_length)
    cipher      = encrypt(column_i, keys_new, key_length)
    plaintext   = decrypt(cipher, keys_new, key_length)
    
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

