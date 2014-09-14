from operator import xor
from itertools import starmap

import os
import sys
import struct
import hashlib


class Pad(object):
    def __init__(self, keyfile, initial_seek=0):
        self._keypath = os.path.join(keyfile)
        self._current_encode_seek = initial_seek
        self._stepping = 2
        self._encode_counter = 0
        self._decode_counter = 0
        self._offset_length = 6
        with open(self._keypath, 'rb') as keypool:
            pass

    def set_seek(self, seek):
        """
        Sets the current position for encoding.
        """
        self._current_encode_seek = seek

    def fetch_encode_block(self, bufsize):
        """
        Takes the size of the encoding block to be returned
        and fetches a block of key using self's stepping value to step 
        through the bytes of the keyfile.
        """
        with open(self._keypath, 'rb') as keypool:
            keypool.seek(self._current_encode_seek)
            keyblock = bytearray(keypool.read(bufsize))
            self._current_encode_seek += self._stepping * len(keyblock)
            return keyblock

    def fetch_decode_block(self, seek, bufsize):
        """
        Takes the size of the encoding block to be returned
        and fetches a block of key using self's stepping value to step 
        through the bytes of the keyfile.
        """
        with open(self._keypath, 'rb') as keypool:
            keypool.seek(seek)
            return bytearray(keypool.read(bufsize))

    def encode(self, plaintext):
        """
        Takes plaintext as bytearray. Generates a 16 byte md5 hash of the 
        entire packet and appends it to the plaintext. Plaintext is xor'ed
        with bytes pulled from keyfile.
        """
        plaintext = bytearray(plaintext)

        # Append the md5sum of the plaintext to it.
        hashish = bytearray(hashlib.md5(str(plaintext)).digest())
        plaintext.extend(hashish)

        # Note the seek before encoding the plaintext.
        seek = self._current_encode_seek

        # Get the keypool and encode the plaintext with it.
        keypool = self.fetch_encode_block(len(plaintext))
        ciphertext = bytearray(starmap(xor, zip(plaintext, keypool)))

        # Append the seek used to do the encoding as a 6 bytes of hex. This
        # allows for a ~256TB maximum keyfile size.
        offset = bytearray.fromhex("{0:012x}".format(seek))
        ciphertext.extend(offset)
        
        self._encode_counter += 1 
        return ciphertext

    def decode(self, ciphertext):
        """
        Takes ciphertext as bytearray. Pops last 6 bytes off the packet.
        Interprets that as an integer (from hex bytes) and uses that
        as the starting offset. Step by 2 to decode rest of payload including
        16 byte md5 checksum of packet. Pop off next 16 bytes and validate 
        rest of packet. Return plaintext packet if checksum is good.
        """
        # Interpret the offset bytes as the decoding seek.
        ciphertext, offset = divide(bytearray(ciphertext), -6)
        seek = struct.unpack(">Q", bytearray('\x00\x00') + offset)[0]
        
        # Chop off the offset bytes

        # Decipher.
        keypool = self.fetch_decode_block(seek, len(ciphertext))
        plaintext = bytearray(starmap(xor, zip(ciphertext, keypool)))

        # Remove and store last 16 bytes from plaintext and md5sum the
        # remaining bytes. If the checksum matches the 16 bytes that
        # were 'popped' off, return the plaintext.
        plaintext, checksum = divide(plaintext, -16)
        realsum = bytearray(hashlib.md5(str(plaintext)).digest())
        if checksum == realsum:
            self._decode_counter += 1
            return plaintext
        return bytearray()
        

def divide(iter, i):
    return iter[:i], iter[i:]
