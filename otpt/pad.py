from operator import xor

import os
import sys
import hashlib


class Pad(object):
    def __init__(self, keyfile, initial_seek=0):
        self._keypath = os.path.join(keyfile)
        self._current_encode_seek = initial_seek
        self._stepping = 2
        self._encode_counter = 0
        self._decode_counter = 0
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
        # print "Encoding Offset: ", self._current_encode_seek
        keypool = open(self._keypath, 'rb')
        keyblock = bytearray()
        for i in range(bufsize):
            keypool.seek(self._current_encode_seek)
            keyblock.append(keypool.read(1))
            self._current_encode_seek += self._stepping
        keypool.close()
        return keyblock

    def fetch_decode_block(self, seek, bufsize):
        """
        Takes the size of the encoding block to be returned
        and fetches a block of key using self's stepping value to step 
        through the bytes of the keyfile.
        """
        # print "Decoding Offset: ", seek
        keypool = open(self._keypath, 'rb')
        keyblock = bytearray()
        for i in range(bufsize):
            keypool.seek(seek)
            keyblock.append(keypool.read(1))
            seek += self._stepping
        keypool.close()
        return keyblock

    def encode(self, plaintext):
        """
        Takes plaintext as bytearray. Generates a 16 byte md5 hash of the 
        entire packet and appends it to the plaintext. Plaintext is xor'ed
        with bytes pulled from keyfile.
        """
        plaintext = bytearray(plaintext)
        # Here we take a hash of the bytestring that was the original packet.
        hashish = bytearray(hashlib.md5(str(plaintext)).digest())

        # We append the bytes that represent the hash of the packet to the end
        # of the packet
        for i in hashish:
            plaintext.append(i)

        # Initialize the ciphertext to be an empty bytearray to be appended to
        # in our cipherloop. Make a note of the current seek in the file, it
        # will be appended to the packet after the cipherloop.
        ciphertext = bytearray()
        offset = bytearray.fromhex(
            "{0:012x}".format(self._current_encode_seek))

        # Cipher loop. Iterate over the bytes in plaintext and xor with the
        # keybytes from the global offset.
        keypool = self.fetch_encode_block(len(plaintext))

        for i in range(len(plaintext)):
            ciphertext.append(xor(plaintext[i], keypool[i]))

        # After the original packet plus the md5 hashish are XOR'ed with the
        # keybytes, the offset within the keyfile is appended as a 6-byte hex
        # number to the packet bytes to be returned. This allows for a ~256TB
        # maximum keyfile size.
        packetbytes = ciphertext
        for i in range(len(offset)):
            packetbytes.append(offset[i])

        self._encode_counter += 1 
        # print "Encode Counter: ", self._encode_counter
        return packetbytes

    def decode(self, ciphertext):
        """
        Takes ciphertext as bytearray. Pops last 6 bytes off the packet.
        Interprets that as an integer (from hex bytes) and uses that
        as the starting offset. Step by 2 to decode rest of payload including
        16 byte md5 checksum of packet. Pop off next 16 bytes and validate 
        rest of packet. Return plaintext packet if checksum is good.
        """
        ## print "ciphertext: ", ciphertext
        # 'Pop' last 6 bytes of ciphertext and interpret as integer offset.
        ciphertext = bytearray(ciphertext)
        offsetbytes = ciphertext[-6:]
        ciphertext = ciphertext[:-6]
        ## print "ciphertext -6: ", ciphertext
        counter = 6
        offset = 0
        ## print "offsetbytes: ", offsetbytes
        for i in offsetbytes:
            counter -= 1
            offset += i * (256 ** counter)

        # Decipher loop.
        keypool = self.fetch_decode_block(offset, len(ciphertext))
        plaintext = bytearray()
        for i in range(len(ciphertext)):
            plaintext.append(xor(ciphertext[i], keypool[i]))

        # Remove and store last 16 bytes from plaintext and md5sum the
        # remaining bytes. If the checksum matches the 16 bytes that
        # were 'popped' off, return the plaintext.
        pktchksum = plaintext[-16:]
        plaintext = plaintext[:-16]
        chksum = bytearray(hashlib.md5(str(plaintext)).digest())
        if pktchksum == chksum:
            self._decode_counter += 1
            # print "Decoding counter: ", self._decode_counter
            return plaintext
        else:
            # print "Dropped packet: ", str(plaintext)
            return bytearray()
