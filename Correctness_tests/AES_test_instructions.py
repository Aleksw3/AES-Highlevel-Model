import sys, os
sys.path.append(os.path.dirname(os.path.dirname(__file__))+"/DOM implementation")
sys.path.append(os.path.dirname(os.path.dirname(__file__))+"/Scalar-crypto instruction implementation")
sys.path.append(os.path.dirname(os.path.dirname(__file__))+"/Standard AES")

import AES_byte_dom_instructions
import AES_byte_instructions
import AES_dom_application
import AES_applicaton
import random

def test_instructions(can_print = False):
    error = False
    bs = 0
    column = 0x22222222
    key    = 0x01234567
    random_value = random.randint(0, 2**(32)-1)

    share1 = column ^ random_value
    share2 = random_value

    protected   = AES_byte_dom_instructions.aes32esi(share1, share2, key, bs)
    unprotected = AES_byte_instructions.aes32esi(column, key, bs)
    if protected != unprotected:
        error = True
    if can_print:
        print(f"ESI: Protected = {protected:08x},  Unprotected = {unprotected:08x}, Are they equal? {'Yes' if protected==unprotected else 'Noooope'}")

    protected   = AES_byte_dom_instructions.aes32esmi(share1, share2, key, bs)
    unprotected = AES_byte_instructions.aes32esmi(column, key, bs)
    if protected != unprotected:
        error = True
    if can_print:
        print(f"ESMI: Protected = {protected:08x},  Unprotected = {unprotected:08x}, Are they equal? {'Yes' if protected==unprotected else 'Noooope'}")

    protected   = AES_byte_dom_instructions.aes32dsi(share1, share2, key, bs)
    unprotected = AES_byte_instructions.aes32dsi(column, key, bs)
    if protected != unprotected:
        error = True
    if can_print:
        print(f"DSI: Protected = {protected:08x},  Unprotected = {unprotected:08x}, Are they equal? {'Yes' if protected==unprotected else 'Noooope'}")

    protected   = AES_byte_dom_instructions.aes32dsmi(share1, share2, key, bs)
    unprotected = AES_byte_instructions.aes32dsmi(column, key, bs)
    if protected != unprotected:
        error = True
    if can_print:
        print(f"DSMI: Protected = {protected:08x},  Unprotected = {unprotected:08x}, Are they equal? {'Yes' if protected==unprotected else 'Noooope'}\n")
    
    return error

def test_keyscheduler(can_print:bool = False):
    key      = [0x74616854, 0x796d2073, 0x6e754b20, 0x75462067,0x74616854, 0x796d2073, 0x6e754b20, 0x75462067]
    key_length = 256
    keys_new   = AES_dom_application.KeyScheduler(key, key_length)
    keys_old   = AES_applicaton.KeyScheduler(key, key_length)
    errors = 0
    for i,j in zip(keys_new, keys_old):
        if can_print:
            print(f"{i:08x} - {j:08x} = {i==j}")
        if i != j:
            errors+=1
    if can_print:
        print(f"Key errors = {errors}\n")

    return errors > 0

def test_encryption(can_print:bool = False):
    column_i = [0x206f7754, 0x20656e4f, 0x656e694e, 0x6f775420]
    key      = [0x74616854, 0x796d2073, 0x6e754b20, 0x75462067]
    key_length = 128

    keys_new = AES_dom_application.KeyScheduler(key, key_length)
    unprot   = AES_applicaton.encrypt(column_i, keys_new, key_length)
    prot     = AES_dom_application.encrypt(column_i, keys_new, key_length)

    errors = 0
    for i,j in zip(prot,unprot):
        if can_print:
            print(f"{i:08x} - {j:08x} = {i==j}")
        if i!= j:
            errors += 1
    if can_print:
        print(f"Encryption errors = {errors}\n")
    
    return errors > 0

def test_decryption(can_print: bool = False):
    column_i = [0x206f7754, 0x20656e4f, 0x656e694e, 0x6f775420]
    key      = [0x74616854, 0x796d2073, 0x6e754b20, 0x75462067]
    key_length = 128
    keys_new   = AES_dom_application.KeyScheduler(key, key_length)

    unprot = AES_applicaton.decrypt(column_i, keys_new, key_length)
    prot   = AES_dom_application.decrypt(column_i, keys_new, key_length)

    errors = 0
    for i,j in zip(prot,unprot):
        if can_print:
            print(f"{i:08x} - {j:08x} = {i==j}")
        if i!= j:
            errors += 1
    if can_print:
        print(f"Decryption errors = {errors}\n")
    return errors > 0

if __name__ == "__main__":
    errors = 0
    errors += test_instructions(can_print = True)
    errors += test_keyscheduler(can_print = True)
    errors += test_encryption(  can_print = True)
    errors += test_decryption(  can_print = True)

    print(F"Number of discrepencies found between protected and unprotected: {errors}")