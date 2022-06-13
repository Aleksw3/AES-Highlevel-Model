from pickletools import uint2, uint4, uint8
from sbox import s_box as sbox, inv_s_box as sbox_inv

def get_bit_by_index(byte: uint8, idx:int):
    assert(idx <= 7)
    return (byte >> idx) & 0b1

class SBox:
    def __init__(self, byte, inverse = False):
        assert(byte <= 255)
        if inverse:
            self.sub_byte = SBox.sbox_inverse(byte)
        else:
            self.sub_byte = SBox.sbox(byte)

    def sbox(byte_in: uint8):
        mapped_byted  = SBox.isomorphic_mapping(byte_in)
        inverted_byte = SBox.GF256.inversion(mapped_byted)
        inverse_mapped_byte     = SBox.inverse_isomorphic_mapping(inverted_byte)
        affine_transformed_byte = SBox.affine_transformation(inverse_mapped_byte)
        return affine_transformed_byte

    def sbox_inverse(byte_in: uint8):
        inverse_affine_transform = SBox.inverse_affine_transformation(byte_in)
        mapped_byted  = SBox.isomorphic_mapping(inverse_affine_transform)
        inverted_byte = SBox.GF256.inversion(mapped_byted)
        inverse_mapped_byte     = SBox.inverse_isomorphic_mapping(inverted_byte)
        return inverse_mapped_byte

    def isomorphic_mapping(byte_in: uint8):
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
        i7 = get_bit_by_index(byte_in, 7)
        i6 = get_bit_by_index(byte_in, 6)
        i5 = get_bit_by_index(byte_in, 5)
        i4 = get_bit_by_index(byte_in, 4)
        i3 = get_bit_by_index(byte_in, 3)
        i2 = get_bit_by_index(byte_in, 2)
        i1 = get_bit_by_index(byte_in, 1)
        i0 = get_bit_by_index(byte_in, 0)

        io7 = i7 ^ i6 ^ i5 ^ i4 ^ i3 ^ 0
        io6 = i6 ^ i5 ^ i4 ^ i3 ^ i2 ^ 1
        io5 = i5 ^ i4 ^ i3 ^ i2 ^ i1 ^ 1
        io4 = i4 ^ i3 ^ i2 ^ i1 ^ i0 ^ 0
        io3 = i7 ^ i3 ^ i2 ^ i1 ^ i0 ^ 0
        io2 = i7 ^ i6 ^ i2 ^ i1 ^ i0 ^ 0
        io1 = i7 ^ i6 ^ i5 ^ i1 ^ i0 ^ 1
        io0 = i7 ^ i6 ^ i5 ^ i4 ^ i0 ^ 1

        return io7 << 7 | io6 << 6 | io5 << 5 | io4 << 4 | io3 << 3 | io2 << 2 | io1 << 1 | io0 << 0
    
    def inverse_affine_transformation(byte_in: uint8):
        i7 = get_bit_by_index(byte_in, 7)
        i6 = get_bit_by_index(byte_in, 6)
        i5 = get_bit_by_index(byte_in, 5)
        i4 = get_bit_by_index(byte_in, 4)
        i3 = get_bit_by_index(byte_in, 3)
        i2 = get_bit_by_index(byte_in, 2)
        i1 = get_bit_by_index(byte_in, 1)
        i0 = get_bit_by_index(byte_in, 0)

        io7 = i6 ^ i4 ^ i1 ^ 0
        io6 = i5 ^ i3 ^ i0 ^ 0
        io5 = i7 ^ i4 ^ i2 ^ 0
        io4 = i6 ^ i3 ^ i1 ^ 0
        io3 = i5 ^ i2 ^ i0 ^ 0
        io2 = i7 ^ i4 ^ i1 ^ 1
        io1 = i6 ^ i3 ^ i0 ^ 0
        io0 = i7 ^ i5 ^ i2 ^ 1

        return io7 << 7 | io6 << 6 | io5 << 5 | io4 << 4 | io3 << 3 | io2 << 2 | io1 << 1 | io0 << 0

    class GF256:
        def inversion(byte_in:uint8):
            nibble_in_high  = (byte_in >> 4) & 0xF
            nibble_in_low   = (byte_in >> 0) & 0xF
            sum_nibbles = nibble_in_high ^ nibble_in_low
            square_scale    = SBox.GF16.square_scale(sum_nibbles)
            multiply_inputs = SBox.GF16.multiplication(nibble_in_high, nibble_in_low)

            sum = square_scale ^ multiply_inputs
            inverted = SBox.GF16.inversion(sum)

            result_h  = SBox.GF16.multiplication(inverted, nibble_in_low)
            result_l  = SBox.GF16.multiplication(inverted, nibble_in_high)
            
            return result_h << 4 | result_l

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

            
        def multiplication(nibble_in_a: uint4, nibble_in_b: uint4):
            a_split_in_2_bits = [(nibble_in_a >> 0) & 0b11, (nibble_in_a >> 2) & 0b11]
            b_split_in_2_bits = [(nibble_in_b >> 0) & 0b11, (nibble_in_b >> 2) & 0b11]

            a_sum_2_bits = a_split_in_2_bits[1] ^ a_split_in_2_bits[0]
            b_sum_2_bits = b_split_in_2_bits[1] ^ b_split_in_2_bits[0]

            a_high_b_high_multiplication = SBox.GF4.multiplication(a_split_in_2_bits[1], b_split_in_2_bits[1])
            a_low_b_low_multiplication   = SBox.GF4.multiplication(a_split_in_2_bits[0], b_split_in_2_bits[0])
            ab_sum_multiplication        = SBox.GF4.multiplication(a_sum_2_bits, b_sum_2_bits)

            scale_ab_sum_mult          = SBox.GF4.scale_N(ab_sum_multiplication)

            result_h = scale_ab_sum_mult ^ a_high_b_high_multiplication
            result_l = scale_ab_sum_mult ^ a_low_b_low_multiplication

            return result_h << 2 | result_l

        def inversion(nibble_in: uint4):
            split_in_bits = [(nibble_in >> 0) & 0b11, (nibble_in >> 2) & 0b11]

            sum_bits = split_in_bits[0] ^ split_in_bits[1]
            square_sum_bits = SBox.GF4.square(sum_bits)
            sum_square_scaled = SBox.GF4.scale_N(square_sum_bits)
            bits_multipled    = SBox.GF4.multiplication(split_in_bits[0], split_in_bits[1])
            
            sum2 = sum_square_scaled ^ bits_multipled
            inversion = SBox.GF4.inverse(sum2)

            result_h = SBox.GF4.multiplication(inversion, split_in_bits[0])
            result_l = SBox.GF4.multiplication(inversion, split_in_bits[1])

            return result_h << 2 | result_l

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

        def scale_N2(bits_in: uint2):
            bits_in_h = ((bits_in >> 1) & 0b01)
            bits_in_l = ((bits_in >> 0) & 0b01) 
            result_h = bits_in_l ^ bits_in_h
            result_l = bits_in_h

            return result_h << 1 | result_l
        
        def square_scale(bits_in: uint2):
            bits_in_h = ((bits_in >> 1) & 0b01)
            bits_in_l = ((bits_in >> 0) & 0b01) 
            result_h = bits_in_l
            result_l =  bits_in_l ^ bits_in_h

            return result_h << 1 | result_l

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
        return self.sub_byte

    def __format__(self, format):
        return f"{self.sub_byte:{format}}"

    def __eq__(self, other):
        return self.sub_byte == other


def main():

    inversion = False
    byte = 10

    sub_byte = SBox(byte, inverse = inversion)
    print(f"Input = {byte:02x} SubByte = {sub_byte:02x}")



if __name__ == "__main__":
    main()