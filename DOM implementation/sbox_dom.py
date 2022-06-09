import random
from pickletools import uint2, uint4, uint8

def get_bit_by_index(byte: uint8, idx:int):
    assert(idx <= 7)
    return (byte >> idx) & 0b1

class SBox:
    def __init__(self, shareA: uint8, shareB: uint8, inverse: bool = False):
        assert(shareA <= 255 and shareB <= 255)
        if inverse:
            self.share1, self.share2 = SBox.sbox_inverse(shareA, shareB)
            self.sub_byte = self.share1 ^ self.share2
        else:
            self.share1, self.share2 = SBox.sbox(shareA, shareB)
            self.sub_byte = self.share1 ^ self.share2


    def sbox(shareA: uint8, shareB: uint8):
        shareA_mapped  = SBox.isomorphic_mapping(shareA)
        shareB_mapped  = SBox.isomorphic_mapping(shareB)

        shareA_inverse, shareB_inverse = SBox.GF256.inversion(shareA_mapped, shareB_mapped)

        shareA_inverse_map     = SBox.inverse_isomorphic_mapping(shareA_inverse)
        shareB_inverse_map     = SBox.inverse_isomorphic_mapping(shareB_inverse)
        

        # Only one of the shares should have the addition in the affine transformation, otherwise it will be cancelled when added together
        shareA_affine_transformed = SBox.affine_transformation(shareA_inverse_map)
        shareB_affine_transformed = SBox.affine_transformation_mult(shareB_inverse_map)

        return shareA_affine_transformed, shareB_affine_transformed

    def sbox_inverse(shareA: uint8, shareB: uint8):
        # Only one of the shares should have the addition in the affine transformation, otherwise it will be cancelled when added together
        shareA_affine_transformed = SBox.inverse_affine_transformation(shareA)
        shareB_affine_transformed = SBox.inverse_affine_transformation_mult(shareB)

        shareA_mapped  = SBox.isomorphic_mapping(shareA_affine_transformed)
        shareB_mapped  = SBox.isomorphic_mapping(shareB_affine_transformed)

        shareA_inverse, shareB_inverse = SBox.GF256.inversion(shareA_mapped, shareB_mapped)

        shareA_inverse_map     = SBox.inverse_isomorphic_mapping(shareA_inverse)
        shareB_inverse_map     = SBox.inverse_isomorphic_mapping(shareB_inverse)

        return shareA_inverse_map, shareB_inverse_map
    
    def isomorphic_mapping(byte_in: uint8):
        # Isomorpic transformation from: Canright "A very compact SBox" : https://calhoun.nps.edu/bitstream/handle/10945/791/NPS-MA-04-001.pdf
        i7 = get_bit_by_index(byte_in, 7)
        i6 = get_bit_by_index(byte_in, 6)
        i5 = get_bit_by_index(byte_in, 5)
        i4 = get_bit_by_index(byte_in, 4)
        i3 = get_bit_by_index(byte_in, 3)
        i2 = get_bit_by_index(byte_in, 2)
        i1 = get_bit_by_index(byte_in, 1)
        i0 = get_bit_by_index(byte_in, 0)

        io7 = i7 ^ i6 ^ i5 ^ i2 ^ i1 ^ i0
        io6 = i6 ^ i5 ^ i4 ^ i0
        io5 = i6 ^ i5 ^ i1 ^ i0
        io4 = i7 ^ i6 ^ i5 ^ i0
        io3 = i7 ^ i4 ^ i3 ^ i1 ^ i0
        io2 = i0
        io1 = i6 ^ i5 ^ i0
        io0 = i6 ^ i3 ^ i2 ^ i1 ^ i0

        return io7 << 7 | io6 << 6 | io5 << 5 | io4 << 4 | io3 << 3 | io2 << 2 | io1 << 1 | io0 << 0

    def inverse_isomorphic_mapping(byte_in: uint8):
        i7 = get_bit_by_index(byte_in, 7)
        i6 = get_bit_by_index(byte_in, 6)
        i5 = get_bit_by_index(byte_in, 5)
        i4 = get_bit_by_index(byte_in, 4)
        i3 = get_bit_by_index(byte_in, 3)
        i2 = get_bit_by_index(byte_in, 2)
        i1 = get_bit_by_index(byte_in, 1)
        i0 = get_bit_by_index(byte_in, 0)

        io7 = i4 ^ i1
        io6 = i7 ^ i6 ^ i5 ^ i3 ^ i1 ^ i0
        io5 = i7 ^ i6 ^ i5 ^ i3 ^ i2 ^ i0
        io4 = i6 ^ i1
        io3 = i6 ^ i5 ^ i4 ^ i3 ^ i2 ^ i1
        io2 = i7 ^ i5 ^ i4 ^ i1
        io1 = i5 ^ i1
        io0 = i2

        return io7 << 7 | io6 << 6 | io5 << 5 | io4 << 4 | io3 << 3 | io2 << 2 | io1 << 1 | io0 << 0

    def affine_transformation(byte_in: uint8):
        affine_mult = SBox.affine_transformation_mult(byte_in)
        return SBox.affine_transformation_add(affine_mult)


    def affine_transformation_mult(byte_in: uint8):
        i7 = get_bit_by_index(byte_in, 7)
        i6 = get_bit_by_index(byte_in, 6)
        i5 = get_bit_by_index(byte_in, 5)
        i4 = get_bit_by_index(byte_in, 4)
        i3 = get_bit_by_index(byte_in, 3)
        i2 = get_bit_by_index(byte_in, 2)
        i1 = get_bit_by_index(byte_in, 1)
        i0 = get_bit_by_index(byte_in, 0)

        io7 = i7 ^ i6 ^ i5 ^ i4 ^ i3
        io6 = i6 ^ i5 ^ i4 ^ i3 ^ i2
        io5 = i5 ^ i4 ^ i3 ^ i2 ^ i1
        io4 = i4 ^ i3 ^ i2 ^ i1 ^ i0
        io3 = i7 ^ i3 ^ i2 ^ i1 ^ i0
        io2 = i7 ^ i6 ^ i2 ^ i1 ^ i0
        io1 = i7 ^ i6 ^ i5 ^ i1 ^ i0
        io0 = i7 ^ i6 ^ i5 ^ i4 ^ i0

        return io7 << 7 | io6 << 6 | io5 << 5 | io4 << 4 | io3 << 3 | io2 << 2 | io1 << 1 | io0 << 0

    def affine_transformation_add(byte_in: uint8):
        i7 = get_bit_by_index(byte_in, 7)
        i6 = get_bit_by_index(byte_in, 6)
        i5 = get_bit_by_index(byte_in, 5)
        i4 = get_bit_by_index(byte_in, 4)
        i3 = get_bit_by_index(byte_in, 3)
        i2 = get_bit_by_index(byte_in, 2)
        i1 = get_bit_by_index(byte_in, 1)
        i0 = get_bit_by_index(byte_in, 0)

        io7 = i7 ^ 0
        io6 = i6 ^ 1
        io5 = i5 ^ 1
        io4 = i4 ^ 0
        io3 = i3 ^ 0
        io2 = i2 ^ 0
        io1 = i1 ^ 1
        io0 = i0 ^ 1

        return io7 << 7 | io6 << 6 | io5 << 5 | io4 << 4 | io3 << 3 | io2 << 2 | io1 << 1 | io0 << 0
    
    def inverse_affine_transformation(byte_in: uint8):
        mult = SBox.inverse_affine_transformation_mult(byte_in)
        return SBox.inverse_affine_transformation_add(mult)

    def inverse_affine_transformation_mult(byte_in: uint8):
        i7 = get_bit_by_index(byte_in, 7)
        i6 = get_bit_by_index(byte_in, 6)
        i5 = get_bit_by_index(byte_in, 5)
        i4 = get_bit_by_index(byte_in, 4)
        i3 = get_bit_by_index(byte_in, 3)
        i2 = get_bit_by_index(byte_in, 2)
        i1 = get_bit_by_index(byte_in, 1)
        i0 = get_bit_by_index(byte_in, 0)

        io7 = i6 ^ i4 ^ i1
        io6 = i5 ^ i3 ^ i0
        io5 = i7 ^ i4 ^ i2
        io4 = i6 ^ i3 ^ i1
        io3 = i5 ^ i2 ^ i0
        io2 = i7 ^ i4 ^ i1
        io1 = i6 ^ i3 ^ i0
        io0 = i7 ^ i5 ^ i2

        return io7 << 7 | io6 << 6 | io5 << 5 | io4 << 4 | io3 << 3 | io2 << 2 | io1 << 1 | io0 << 0

    def inverse_affine_transformation_add(byte_in: uint8):
        i7 = get_bit_by_index(byte_in, 7)
        i6 = get_bit_by_index(byte_in, 6)
        i5 = get_bit_by_index(byte_in, 5)
        i4 = get_bit_by_index(byte_in, 4)
        i3 = get_bit_by_index(byte_in, 3)
        i2 = get_bit_by_index(byte_in, 2)
        i1 = get_bit_by_index(byte_in, 1)
        i0 = get_bit_by_index(byte_in, 0)

        io7 = i7 ^ 0
        io6 = i6 ^ 0
        io5 = i5 ^ 0
        io4 = i4 ^ 0
        io3 = i3 ^ 0
        io2 = i2 ^ 1
        io1 = i1 ^ 0
        io0 = i0 ^ 1

        return io7 << 7 | io6 << 6 | io5 << 5 | io4 << 4 | io3 << 3 | io2 << 2 | io1 << 1 | io0 << 0          
        
    class GF256:
        def inversion(shareA: uint8, shareB: uint8):
            shareA_nibbles = [(shareA >> 0) & 0xF, (shareA >> 4) & 0xF]
            shareB_nibbles = [(shareB >> 0) & 0xF, (shareB >> 4) & 0xF]

            sum_shareA_nibbles = shareA_nibbles[0] ^ shareA_nibbles[1]
            sum_shareB_nibbles = shareB_nibbles[0] ^ shareB_nibbles[1]

            shareA_square_scale = SBox.GF16.square_scale(sum_shareA_nibbles)
            shareB_square_scale = SBox.GF16.square_scale(sum_shareB_nibbles)

            shareA_multiply, shareB_multiply = SBox.GF16.dom_multiplication(shareA_nibbles[0], shareA_nibbles[1], shareB_nibbles[0], shareB_nibbles[1])

            shareA_sum_multiply = shareA_multiply ^ shareA_square_scale
            shareB_sum_multiply = shareB_multiply ^ shareB_square_scale

            shareA_inverted, shareB_inverted = SBox.GF16.inversion(shareA_sum_multiply, shareB_sum_multiply)

            shareA_result_h, shareB_result_h  = SBox.GF16.dom_multiplication(shareA_nibbles[0], shareA_inverted, shareB_nibbles[0], shareB_inverted)
            shareA_result_l, shareB_result_l  = SBox.GF16.dom_multiplication(shareA_nibbles[1], shareA_inverted, shareB_nibbles[1], shareB_inverted)

            return shareA_result_h << 4 | shareA_result_l, shareB_result_h << 4 | shareB_result_l

    class GF16:
        def square(nibble_in: uint4):
            split_in_2_bits = [(nibble_in >> 0) & 0b11, (nibble_in >> 2) & 0b11]
            square_2_bits   = [SBox.GF4.square(split_in_2_bits[0]), SBox.GF4.square(split_in_2_bits[1])]

            sum_squares     = square_2_bits[0] ^ square_2_bits[1]
            scaled_sum_squares = SBox.GF4.scale_N(sum_squares)

            result_h = scaled_sum_squares ^ square_2_bits[1] 
            result_l = scaled_sum_squares ^ square_2_bits[0]

            return result_h << 2 | result_l

        def scale_v(nibble_in: uint4):
            split_in_2_bits = [(nibble_in >> 0) & 0b11, (nibble_in >> 2) & 0b11]

            sum_2_bits     = split_in_2_bits[0] ^ split_in_2_bits[1]
            scaled_sum_2_bits = SBox.GF4.scale_N(sum_2_bits)

            result_h = scaled_sum_2_bits ^ split_in_2_bits[1] 
            result_l = scaled_sum_2_bits ^ split_in_2_bits[0]

            return result_h << 2 | result_l

        def square_scale(nibble_in: uint4):
            split_in_2_bits = [(nibble_in >> 0) & 0b11, (nibble_in >> 2) & 0b11]

            sum_bits = split_in_2_bits[0] ^ split_in_2_bits[1]

            square_sum = SBox.GF4.square(sum_bits)

            scale_h = SBox.GF4.scale_N(split_in_2_bits[0])
            square_scale_h = SBox.GF4.square(scale_h)

            result_h = square_sum
            result_l = square_scale_h

            return result_h << 2 | result_l

            
        def dom_multiplication(shareA_l, shareA_h, shareB_l, shareB_h):
            additional_random = 0#random.randint(0, 15)
            AA_hl_mult = SBox.GF16.multiplication(shareA_h, shareA_l)
            AB_hl_mult = SBox.GF16.multiplication(shareA_h, shareB_l)
            BB_hl_mult = SBox.GF16.multiplication(shareB_h, shareB_l)
            BA_hl_mult = SBox.GF16.multiplication(shareB_h, shareA_l)

            AB_hl_mult_r = AB_hl_mult ^ additional_random
            BA_hl_mult_r = BA_hl_mult ^ additional_random

            result_shareA = AA_hl_mult ^ AB_hl_mult_r
            result_shareB = BB_hl_mult ^ BA_hl_mult_r

            return result_shareA, result_shareB

        @staticmethod
        def multiplication(nibble_in_a: uint4, nibble_in_b: uint4):
            a_split_in_2_bits = [(nibble_in_a >> 0) & 0b11, (nibble_in_a >> 2) & 0b11]
            b_split_in_2_bits = [(nibble_in_b >> 0) & 0b11, (nibble_in_b >> 2) & 0b11]

            a_sum_2_bits = a_split_in_2_bits[1] ^ a_split_in_2_bits[0]
            b_sum_2_bits = b_split_in_2_bits[1] ^ b_split_in_2_bits[0]

            a_high_b_high_multiplication = SBox.GF4.multiplication(a_split_in_2_bits[1], b_split_in_2_bits[1])
            a_low_b_low_multiplication   = SBox.GF4.multiplication(a_split_in_2_bits[0], b_split_in_2_bits[0])
            ab_sum_multiplication        = SBox.GF4.multiplication(a_sum_2_bits, b_sum_2_bits)

            scale_ab_sum_mult            = SBox.GF4.scale_N(ab_sum_multiplication)

            result_h = scale_ab_sum_mult ^ a_high_b_high_multiplication
            result_l = scale_ab_sum_mult ^ a_low_b_low_multiplication

            return result_h << 2 | result_l

        def inversion(shareA: uint4, shareB: uint4):
            shareA_split_2_bits = [(shareA >> 0) & 0b11, (shareA >> 2) & 0b11]
            shareB_split_2_bits = [(shareB >> 0) & 0b11, (shareB >> 2) & 0b11]

            shareA_sum = shareA_split_2_bits[0] ^ shareA_split_2_bits[1]
            shareB_sum = shareB_split_2_bits[0] ^ shareB_split_2_bits[1]

            shareA_square       = SBox.GF4.square(shareA_sum)
            shareA_square_scale = SBox.GF4.scale_N(shareA_square)
            shareB_square       = SBox.GF4.square(shareB_sum)
            shareB_square_scale = SBox.GF4.scale_N(shareB_square)

            shareA_multiply, shareB_multiply = SBox.GF4.dom_multiplication(shareA_split_2_bits[0], shareA_split_2_bits[1], shareB_split_2_bits[0], shareB_split_2_bits[1])

            shareA_sum_multiply = shareA_multiply ^ shareA_square_scale
            shareB_sum_multiply = shareB_multiply ^ shareB_square_scale

            shareA_inverted_sum = SBox.GF4.inverse(shareA_sum_multiply)
            shareB_inverted_sum = SBox.GF4.inverse(shareB_sum_multiply)

            shareA_result_h, shareB_result_h = SBox.GF4.dom_multiplication(shareA_split_2_bits[0], shareA_inverted_sum, shareB_split_2_bits[0], shareB_inverted_sum)
            shareA_result_l, shareB_result_l = SBox.GF4.dom_multiplication(shareA_split_2_bits[1], shareA_inverted_sum, shareB_split_2_bits[1], shareB_inverted_sum)


            return shareA_result_h << 2 | shareA_result_l, shareB_result_h << 2 | shareB_result_l

    class GF4:
        def square(bits_in: uint2):
            return (bits_in & 0b10) >> 1 | (bits_in & 0b01) << 1

        def inverse(bits_in: uint2):
            return (bits_in & 0b10) >> 1 | (bits_in & 0b01) << 1

        def scale_N(bits_in: uint2):
            split_in_bit = [(bits_in >> 0) & 0b1, (bits_in >> 1) & 0b1]
            
            result_h = split_in_bit[0]
            result_l = split_in_bit[0] ^ split_in_bit[1]

            return result_h << 1 | result_l
        
        def square_scale(bits_in: uint2):
            bits_in_h = ((bits_in >> 1) & 0b01)
            bits_in_l = ((bits_in >> 0) & 0b01)

            result_h = bits_in_l
            result_l =  bits_in_l ^ bits_in_h

            return result_h << 1 | result_l

        def dom_multiplication(shareA_l, shareA_h, shareB_l, shareB_h):
            additional_random = 0#random.randint(0, 3)
            AA_hl_mult = SBox.GF4.multiplication(shareA_h, shareA_l)
            AB_hl_mult = SBox.GF4.multiplication(shareA_h, shareB_l)
            BB_hl_mult = SBox.GF4.multiplication(shareB_h, shareB_l)
            BA_hl_mult = SBox.GF4.multiplication(shareB_h, shareA_l)

            AB_hl_mult_r = AB_hl_mult ^ additional_random
            BA_hl_mult_r = BA_hl_mult ^ additional_random

            result_shareA = AA_hl_mult ^ AB_hl_mult_r
            result_shareB = BB_hl_mult ^ BA_hl_mult_r

            return result_shareA, result_shareB

        def multiplication(a_bits_in: uint2, b_bits_in: uint2):
            a_split_in_bit = [(a_bits_in >> 0) & 0b01, (a_bits_in >> 1)&0b1]
            b_split_in_bit = [(b_bits_in >> 0) & 0b01, (b_bits_in >> 1)&0b1]

            a_sum_bits = a_split_in_bit[1] ^ a_split_in_bit[0]
            b_sum_bits = b_split_in_bit[1] ^ b_split_in_bit[0]

            a_msb_b_msb_multiplication = a_split_in_bit[1] & b_split_in_bit[1]
            a_lsb_b_lsb_multiplication = a_split_in_bit[0] & b_split_in_bit[0]

            a_sum_b_sum_multiplication  = a_sum_bits & b_sum_bits

            result_h = a_msb_b_msb_multiplication ^ a_sum_b_sum_multiplication
            result_l = a_lsb_b_lsb_multiplication ^ a_sum_b_sum_multiplication

            return result_h << 1 | result_l

    def __str__(self):
        return f"{self.sub_byte:02x}"

    def __format__(self, format):
        return f"{self.sub_byte:{format}}"

    def __eq__(self, other):
        return self.sub_byte == other


def main():
    inversion = False

    byte = random.randint(0, 255)
    mask = random.randint(0, 255)
    
    shareA = byte ^ mask
    shareB = mask

    sub_byte = SBox(shareA = shareA, shareB = shareB, inverse = inversion)
    print(f"Input byte = 0x{byte:02x}, mask = 0x{mask:02x}")
    print(f"SubByte    = 0x{sub_byte:02x}")



if __name__ == "__main__":
    main()
