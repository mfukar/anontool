#!/usr/bin/env python
# @file         home/mfukar/src/anontool/test/AES_ECB_test.py
# @author       Michael Foukarakis
# @version      0.1
# @date         Created:     Tue Jan 25, 2011 07:55 GTB Standard Time
#               Last Update: Tue Feb 08, 2011 10:54 EET
#------------------------------------------------------------------------
# Description:  Unit test for anontool's AES implementation in ECB mode
#------------------------------------------------------------------------
# History:      None yet.
# TODO:         Lots.
#------------------------------------------------------------------------

import sys
from ctypes import *

nidslib = CDLL('../lib/libnids.so', RTLD_GLOBAL)
anonlib = CDLL('../lib/anonlib.so')

class AES_context(Structure):
        _fields_ = [("erk", c_uint * 64), ("drk", c_uint * 64), ("nr", c_int)]
class Buffer(Structure):
        _fields_ = [("b", c_ubyte * 16)]
class Key(Structure):
        _fields_ = [("b", c_ubyte * 32)]

def AES_ECB_test():
        AES_ctx = AES_context()
        AES_enc_result=[[ 0xA0, 0x43, 0x77, 0xAB, 0xE2, 0x59, 0xB0, 0xD0, 0xB5, 0xBA, 0x2D, 0x40, 0xA5, 0x01, 0x97, 0x1B ],
                        [ 0x4E, 0x46, 0xF8, 0xC5, 0x09, 0x2B, 0x29, 0xE2, 0x9A, 0x97, 0x1A, 0x0C, 0xD1, 0xF6, 0x10, 0xFB ],
                        [ 0x1F, 0x67, 0x63, 0xDF, 0x80, 0x7A, 0x7E, 0x70, 0x96, 0x0D, 0x4C, 0xD3, 0x11, 0x8E, 0x60, 0x1A ]]
        AES_dec_result=[[ 0xF5, 0xBF, 0x8B, 0x37, 0x13, 0x6F, 0x2E, 0x1F, 0x6B, 0xEC, 0x6F, 0x57, 0x20, 0x21, 0xE3, 0xBA ],
                        [ 0xF1, 0xA8, 0x1B, 0x68, 0xF6, 0xE5, 0xA6, 0x27, 0x1A, 0x8C, 0xB2, 0x4E, 0x7D, 0x94, 0x91, 0xEF ],
                        [ 0x4D, 0xE0, 0xC6, 0xDF, 0x7C, 0xB1, 0x69, 0x72, 0x84, 0x60, 0x4D, 0x60, 0x27, 0x1B, 0xC5, 0x9A ]]
        for mode in ["encryption", "decryption"]:
                for keylen in [128, 192, 256]:
                        buf = Buffer()
                        key = Key()
                        n = (keylen - 128) / 64
                        for i in range(400):
                                anonlib.aes_schedule_key(byref(AES_ctx), byref(key), keylen)
                                for j in range(9999):
                                        if mode == "encryption":
                                                anonlib.aes_encrypt(byref(AES_ctx), byref(buf), byref(buf))
                                        if mode == "decryption":
                                                anonlib.aes_decrypt(byref(AES_ctx), byref(buf), byref(buf))
                                if keylen != 128:
                                        for j in range(n << 3):
                                                key.b[j] ^= buf.b[j + 16 - (n << 3)]
                                if mode == "encryption":
                                        anonlib.aes_encrypt(byref(AES_ctx), byref(buf), byref(buf))
                                if mode == "decryption":
                                        anonlib.aes_decrypt(byref(AES_ctx), byref(buf), byref(buf))
                                for j in range(16):
                                        key.b[j + (n << 3)] ^= buf.b[j]
                        result = [byte for byte in buf.b]
                        if mode == "encryption":
                                if result != AES_enc_result[n]:
                                        raise AssertionError("[-] Rijndael Monte Carlo Test (ECB mode)\n{0} - Key size {1} bits: failed".format(mode, keylen))
                        else:
                                if result != AES_dec_result[n]:
                                        raise AssertionError("[-] Rijndael Monte Carlo Test (ECB mode)\n{0} - Key size {1} bits: failed".format(mode, keylen))

if __name__ == '__main__':
        try:
                AES_ECB_test()
        except AssertionError, err:
                print err
        else:
                print("[+] Rijndael Monte Carlo Test (ECB mode): Passed")
