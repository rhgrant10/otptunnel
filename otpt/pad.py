from operator import xor
from itertools import starmap

import os
import sys
import struct
import hashlib


class Pad(object):
    """A one-time pad for encrypting and decrypting messages."""
    def __init__(self, keyfile, initial_seek=0):
        self._keypath = os.path.join(keyfile)
        self._current_encode_seek = initial_seek
        self._stepping = 2
        self._encode_counter = 0
        self._decode_counter = 0
        with open(self._keypath, 'rb') as keypool:
            pass

    def set_seek(self, seek):
        """Sets the current position for encoding."""
        self._current_encode_seek = seek

    def fetch_encode_block(self, bufsize):
        """Returns the next bufsize bytes of the pad."""
        with open(self._keypath, 'rb') as keypool:
            keypool.seek(self._current_encode_seek)
            keyblock = bytearray(keypool.read(bufsize))
            self._current_encode_seek += self._stepping * len(keyblock)
            return keyblock

    def fetch_decode_block(self, seek, bufsize):
        """Returns bufsize bytes of the pad starting at seek."""
        with open(self._keypath, 'rb') as keypool:
            keypool.seek(seek)
            return bytearray(keypool.read(bufsize))

    def encode(self, plaintext):
        """Return an encrypted copy of plaintext."""
        plaintext = bytearray(plaintext)

        # Extend the plaintext by its md5sum.
        hashish = bytearray(hashlib.md5(str(plaintext)).digest())
        plaintext.extend(hashish)

        # Note the seek before encoding the plaintext.
        seek = self._current_encode_seek

        # Get the keypool and encode the plaintext with it.
        keypool = self.fetch_encode_block(len(plaintext))
        ciphertext = bytearray(starmap(xor, zip(plaintext, keypool)))

        # Append the seek used to do the encoding as 6 bytes of hex. This allows
        # for a ~256TB maximum keyfile size.
        offset = bytearray.fromhex("{0:012x}".format(seek))
        ciphertext.extend(offset)
        
        self._encode_counter += 1 
        return ciphertext

    def decode(self, ciphertext):
        """Return a decrypted copy of ciphertext."""
        # Interpret the offset bytes as the decoding seek.
        ciphertext, offset = _divide(bytearray(ciphertext), -6)
        seek = struct.unpack(">Q", bytearray('\x00\x00') + offset)[0]
        
        # Decode the ciphertext.
        keypool = self.fetch_decode_block(seek, len(ciphertext))
        plaintext = bytearray(starmap(xor, zip(ciphertext, keypool)))

        # Interpret the last 16 bytes as the checksum.
        plaintext, checksum = _divide(plaintext, -16)
        
        # Ensure real sum matches checksum.
        realsum = bytearray(hashlib.md5(str(plaintext)).digest())
        if checksum != realsum:
            return bytearray()
        
        self._decode_counter += 1
        return plaintext
        

def _divide(seq, i):
    return seq[:i], seq[i:]
