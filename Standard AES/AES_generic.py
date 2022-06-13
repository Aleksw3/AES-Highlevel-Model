from sbox import s_box, inv_s_box

class KeyScheduler:
    def __init__(self, key, key_length):
        self.key = key
        self.key_length = key_length
        self.round_keys = []
        self.rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 
                     0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d]
        
        self.test()
        
        self.round_keys = self.key_scheduler(key_length = key_length, key = key)
        self.round_keys = self.split_key_in_bytes(self.round_keys)


    def key_scheduler(self, key_length, key):
        N = key_length//32
        rounds = 10 if key_length == 128 else 12 if key_length == 192 else 14
        
        keys = []

        for round in range(4*rounds+4):
            if round < N:
                keys.append((key >> ((N-round- 1)*32)) & 0xFFFFFFFF)
            elif round >= N and round % N == 0:
                w_i_1    = keys[-1]
                w_i_N    = keys[-1*N]
                w_rot = (w_i_1 & 0x00FFFFFF)<<8 | (w_i_1 & 0xFF000000)>>24
                w_sub = 0
                for i in range(4):
                    w_sub |= s_box[ (w_rot >> (i*8) ) & 0xFF ] << ( i * 8 )

                w_mod = w_sub ^ self.rcon[round//N - 1] << 24
                w_i   = w_mod ^ w_i_N

                keys.append(w_i)
            elif round >=  N and N > 6 and round % N == 4:
                w_i_N = keys[-N]
                w_i_1_sub = 0
                for i in range(4):
                    w_i_1_sub |= s_box[ (keys[-1] >> (i*8) ) & 0xFF ] << ( i * 8 )
                keys.append(w_i_N ^ w_i_1_sub)
            else:
                w_i_1 = keys[-1]
                w_i_N = keys[-N]
                keys.append(w_i_1 ^ w_i_N)
        return keys

    def split_key_in_bytes(self, keys):
        keys_byte  = []
        round_keys = []  
        for key_32bit in keys:
            keys_byte.extend([(key_32bit>>(3 - i)*8) & 0xFF for i in range(4)]) 
            assert(keys_byte[-4] <= 255)

        for byte_i, byte in enumerate(keys_byte):
            if byte_i % (128//8) == 0:
                round_keys.append([])
            round_keys[-1].extend([byte])
        for key in round_keys:
            assert(len(key) == 128//8)
        print(f"Number of keys = {len(round_keys)}")

        return round_keys

    def test(self):
        _test_key  = 0x0f1571c947d9e8590cb7add6af7f6798
        _test_length = 128
        test_keys = self.key_scheduler(key_length = _test_length, key = _test_key)

        assert(test_keys[4] == 0xdc9037b0)
        assert(test_keys[5] == 0x9b49dfe9)
        assert(test_keys[6] == 0x97fe723f)
        assert(test_keys[7] == 0x388115a7)


    def __str__(self):
        tmp = ""
        for i, round in enumerate(self.round_keys):
            tmp+= f"\n{i:0>2} - "
            for j, byte in enumerate(round):
                tmp += " " if (j % 4 == 0 and j > 0) else ""
                tmp += f"{byte:02x}"
                
        return tmp

class AES:
    def __init__(self, key: KeyScheduler, msg: str):
        self.key = key
        self.message = self.msg_to_bin_packet(msg)
        self.cipher = 0
        self.decipher = []

    def msg_to_bin_packet(self, msg: str):
        packets = []
        tmp = []
        for c in msg:
            tmp.append(ord(c))
            if len(tmp) == 128//8:
                packets.append(tmp)
                tmp = []
        if len(tmp) > 0:
            while len(tmp) < 128//8:
                tmp = [0] + tmp
            packets.append(tmp)
        for packet in packets:
            assert(len(packet) == 128//8)

        return packets

    def encrypt(self):
        keys = self.key.round_keys
        cipher = 0
        encrypted_msg = []
        for block in self.message:
            cipher = self.AddRoundKey(msg = block, key = keys[0])
            print(f"XOR: {cipher[0]:02x}{cipher[1]:02x}{cipher[2]:02x}{cipher[3]:02x}")

            
            
            for key in keys[1:-1]:
                cipher = self.SubBytes(   msg = cipher)
                cipher = self.ShiftBytes( msg = cipher)
                cipher = self.MixColumns( msg = cipher)
                cipher = self.AddRoundKey(msg = cipher, key = key)
                print(f"Encrypted block: {cipher[0]:02x}{cipher[1]:02x}{cipher[2]:02x}{cipher[3]:02x}")

            cipher = self.SubBytes(   msg = cipher)
            cipher = self.ShiftBytes( msg = cipher)
            cipher = self.AddRoundKey(msg = cipher, key = keys[-1])
            
            encrypted_msg.append(cipher)
        self.cipher = encrypted_msg

    def decrypt(self):
        keys = self.key.round_keys[::-1]
        decipher = 0
        encrypted_msg = []
        for block in self.cipher:
            decipher = self.AddRoundKey(msg = block, key = keys[0])
            
            for key in keys[1:-1]:
                decipher = self.InvShiftBytes( msg = decipher)
                decipher = self.InvSubBytes(   msg = decipher)                
                decipher = self.AddRoundKey(msg = decipher, key = key)
                decipher = self.InvMixColumns( msg = decipher)

            decipher = self.InvShiftBytes( msg = decipher)
            decipher = self.InvSubBytes(   msg = decipher)
            decipher = self.AddRoundKey(   msg = decipher, key = keys[-1])
            
            encrypted_msg.append(decipher)
        self.decipher = encrypted_msg
    
    def SubBytes(self, msg):
        assert(len(msg) == 128//8)
        return [s_box[byte] for byte in msg]

    def ShiftBytes(self, msg):
        assert(len(msg) == 128//8)
        for i in range(1, 4): # 4 Rows
            row = [msg[col*4 + i] for col in range(4)]
            row = row[i:] + row[0:i]

            for col in range(4):
                msg[col*4 + i] = row[col]
        return msg

    def AddRoundKey(self, msg, key):
        assert(len(msg) == 128//8)
        assert(len(key) == 128//8)
        new_msg = []
        for msg_byte, key_byte in zip(msg, key):
            new_msg.append(msg_byte ^ key_byte)

        return new_msg

    def MixColumns(self, msg):
        new_msg = msg[:]
        assert(len(new_msg) == 128 //8)
        for col_idx in range(4):
            col = new_msg[col_idx*4:col_idx*4+4]
            b = []
            for byte in col:
                h = 0xff if ((byte >> 7) & 0x01) else 0
                byte = (byte << 1)&0xFF
                b.append(byte ^ (h & 0x1B))
                assert(b[-1] <= 255)
                assert(byte  <= 255)
            assert(len(b) == 4)
            t = [0,0,0,0]

            t[0] = b[0] ^ col[3] ^ col[2] ^ b[1] ^ col[1] # 2a0 + a3 + a2 + 3a1
            t[1] = b[1] ^ col[0] ^ col[3] ^ b[2] ^ col[2] # 2a1 + a0 + a3 + 3a2
            t[2] = b[2] ^ col[1] ^ col[0] ^ b[3] ^ col[3] # 2a2 + a1 + a0 + 3a3
            t[3] = b[3] ^ col[2] ^ col[1] ^ b[0] ^ col[0] # 2a3 + a2 + a1 + 3a0
            
            new_msg[col_idx*4:col_idx*4+4] = t
            for col_v in t:
                assert(col_v <= 255)

        return new_msg
    @staticmethod
    def InvMixColumns(self, msg):
        new_msg = msg[:]
        assert(len(new_msg) == 128 //8)
        for col_idx in range(4):
            col = new_msg[col_idx*4:col_idx*4+4]
            a = []
            b = []
            c = []
            d = []
            for i in range(4):
                a.append(col[i])

                h = 0xff if ((a[i] >> 7) & 0x01) else 0
                b.append(((a[i] << 1)&0xFF) ^ (h & 0x1B))

                h = 0xff if ((b[i] >> 7) & 0x01) else 0
                c.append(((b[i] << 1)&0xFF) ^ (h & 0x1B))

                h = 0xff if ((c[i] >> 7) & 0x01) else 0
                d.append(((c[i] << 1)&0xFF) ^ (h & 0x1B))

            t = [0,0,0,0]

            """
                a[n] = 1*a[n]
                b[n] = 2*a[n]
                c[n] = 4*a[n]
                d[n] = 8*a[n]
                Add these together to create the polynomials:
                t0 = 14*a0 + 9*a3 + 13*a2 + 11*a1
                t1 = 14*a1 + 9*a0 + 13*a3 + 11*a2
                t2 = 14*a2 + 9*a1 + 13*a0 + 11*a3 
                t3 = 14*a3 + 9*a2 + 13*a1 + 11*a0
            """
            t[0] = d[0]^c[0]^b[0]   ^ d[3]^a[3]  ^ d[2]^c[2]^a[2] ^ d[1]^b[1]^a[1] #14*a0 + 9*a3 + 13*a2 + 11*a1
            t[1] = d[1]^c[1]^b[1]   ^ d[0]^a[0]  ^ d[3]^c[3]^a[3] ^ d[2]^b[2]^a[2] #14*a1 + 9*a0 + 13*a3 + 11*a2
            t[2] = d[2]^c[2]^b[2]   ^ d[1]^a[1]  ^ d[0]^c[0]^a[0] ^ d[3]^b[3]^a[3] #14*a2 + 9*a1 + 13*a0 + 11*a3 
            t[3] = d[3]^c[3]^b[3]   ^ d[2]^a[2]  ^ d[1]^c[1]^a[1] ^ d[0]^b[0]^a[0] #14*a3 + 9*a2 + 13*a1 + 11*a0
            
            new_msg[col_idx*4:col_idx*4+4] = t
            for col_v in t:
                assert(col_v <= 255)

        return new_msg

    @staticmethod
    def InvSubBytes(self, msg):
        assert(len(msg) == 128//8)
        return [inv_s_box[byte] for byte in msg]
    
    @staticmethod
    def InvShiftBytes(self, msg):
        assert(len(msg) == 128//8)
        for i in range(1, 4): # 4 Rows
            row = [msg[col*4 + i] for col in range(4)]
            row = row[4 - i:] + row[0:4 - i]

            for col in range(4):
                msg[col*4 + i] = row[col]
        return msg
    
    def __str__(self):
        tmp_msg = ""
        for block in self.message:
            for i, byte in enumerate(block):
                tmp_msg += " " if i%4 == 0 and i > 0 else ""
                tmp_msg += f"{byte:02x}"

        tmp_enc = ""
        for block in self.cipher:
            for i, byte in enumerate(block):
                tmp_enc += " " if i%4 == 0 and i > 0 else ""
                tmp_enc += f"{byte:02x}"
        
        tmp_dec = ""
        for block in self.decipher:
            for byte in block:
                tmp_dec += chr(byte)
        return f"\nMsg       = {tmp_msg} \nEncrypted = {tmp_enc} \nDecrypted = {tmp_dec}\n"

        

if __name__ == "__main__":
    msg = "Two One Nine Two"
    key = 0x5468617473206d79204b756e67204675
    key_length = 128
    key = KeyScheduler(key=key, key_length=key_length)
    print(key)

    aes = AES(key, msg)
    aes.encrypt()
    aes.decrypt()
    print(aes)


