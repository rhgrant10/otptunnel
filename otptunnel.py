import argparse
import textwrap
import socket
from operator import xor
import os
import sys
import select
import errno
import hashlib
import pynetlinux

class OTP(object):

    def __init__(self, keyfile, initial_seek):
        self._keypath = os.path.join(keyfile)
        self._current_encode_seek = initial_seek
        self._stepping = 2
	self._encode_counter = 0
	self._decode_counter = 0
        try:
            keypool = open(self._keypath, 'rb')
        except:
            sys.exit('Invalid keyfile specified')
        keypool.close()

    def fetch_encode_block(self, bufsize):
        """
        Takes the size of the encoding block to be returned
        and fetches a block of key using self's stepping value to step 
        through the bytes of the keyfile.
        """
	print "Encoding Offset: ", self._current_encode_seek
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
	print "Decoding Offset: ", seek
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
	print "Encode Counter: ", self._encode_counter
        return packetbytes

    def decode(self, ciphertext):
        """
        Takes ciphertext as bytearray. Pops last 6 bytes off the packet.
        Interprets that as an integer (from hex bytes) and uses that
        as the starting offset. Step by 2 to decode rest of payload including
        16 byte md5 checksum of packet. Pop off next 16 bytes and validate 
        rest of packet. Return plaintext packet if checksum is good.
        """
        #print "ciphertext: ", ciphertext
        # 'Pop' last 6 bytes of ciphertext and interpret as integer offset.
        ciphertext = bytearray(ciphertext)
        offsetbytes = ciphertext[-6:]
        ciphertext = ciphertext[:-6]
        #print "ciphertext -6: ", ciphertext
        counter = 6
        offset = 0
        #print "offsetbytes: ", offsetbytes
        for i in offsetbytes:
            counter -= 1
            offset += i * (256 ** counter)
            print "offset: ", offset

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
	    print "Decoding counter: ", self._decode_counter
            return plaintext
        else:
            return bytearray()


class OTPTunnel(object):

    '''
    OTPTunnel initializes a TAP interface and instanciates an OTP object which
    is used to encode and decode packets throughout the main_loop.
    '''

    def __init__(self, taddr, tmask, tmtu, laddr, lport, remote_address,
                 remote_port, keyfile, server):
        self._tap = pynetlinux.tap.Tap()
        self._tap.set_ip(taddr)
        self._tap.set_netmask(int(tmask))
        self._tmtu = tmtu
        self._tap.up()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind((laddr, lport))
        self._remote_address = remote_address
        self._remote_port = remote_port
        if server == False:
            self._key = OTP(keyfile, 0)
        else:
            self._key = OTP(keyfile, 1)

    def run(self):
        mtu = self._tmtu
        r = [self._tap, self._sock]
        w = []
        x = []
        to_tap = ''
        to_sock = ''
        while True:
            try:
                r, w, x = select.select(r, w, x)
                if self._tap in r:
                    # Read packet generated by client on the TAP.
                    to_sock = self._tap.read(mtu)

                if self._sock in r:
                    # Read packet from socket. addr[0] is the remote ip
                    # and addr[1] is the remote port.
                    to_tap, addr = self._sock.recvfrom(65535)

                    # Decode incoming packet. Reassign to to_tap.
                    to_tap = self._key.decode(to_tap)

                    # Drop packets found on the socket if they are not from
                    # the server that we inteded to communicate with
                    if addr[0] != self._remote_address or addr[1] != self._remote_port:
                        to_tap = ''  # drop packet
                if self._tap in w:
                    # Begin write section of main loop. Only control packets and
                    # encoded packets received from socket should be processed
                    # here.
                    self._tap.write(to_tap)
                    to_tap = ''
                if self._sock in w:
                    # Packets read in from the TAP are encoded and written
                    # to the socket as bytes. The socket.sendto() function
                    # encapsulates the encoded payload with the appropriate
                    # Ethernet/IP/UDP headers.
                    to_sock = self._key.encode(to_sock)
                    self._sock.sendto(
                        to_sock, (self._remote_address, self._remote_port))
                    to_sock = ''
                r = []
                w = []
                if to_tap:
                    w.append(self._tap)
                else:
                    r.append(self._sock)
                if to_sock:
                    w.append(self._sock)
                else:
                    r.append(self._tap)
            except (select.error, socket.error) as e:
                if e[0] == errno.EINTR:
                    continue
                print >> sys.stderr, str(e)
                break


def main():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent('''\
        A VPN-like server/client that utilizes a user specified
        one time pad for the XOR'ing of network traffic over a TAP interface.
        '''),
        epilog=textwrap.dedent('''\
        
        Examples:
        
        To start a server listening on default settings,

        otptunnel -S -K ~/random.bin  
        
        If that server's IP is 192.168.1.1, and you have the same keyfile
        in your home directory, you can connect to it using,  

        otptunnel -K ~/random.bin -A 192.168.1.1 --tap-addr 10.8.0.2

        '''))
    parser.add_argument('-S', '--server', action="store_true", dest='server',
                        help="set server mode (default: client mode)")
    parser.add_argument('-K', dest='keyfile', help='file to be used as key')
    parser.add_argument('-A', dest='remote_address',
                        help='set remote server address')
    parser.add_argument('-P', type=int, dest='remote_port', default='12000',
                        help='set remote server port')
    parser.add_argument(
        '--tap-addr', type=str, dest='taddr', default='10.8.0.1',
        help='set tunnel local address (default: 10.8.0.1)')
    parser.add_argument('--tap-netmask', default='24', dest='tmask',
                        help='set tunnel netmask (default: 24)')
    parser.add_argument('--tap-mtu', type=int, default=32768, dest='tmtu',
                        help='set tunnel MTU (default: 32768)')
    parser.add_argument('--local-addr', default='0.0.0.0', dest='laddr',
        help='address to which OTPTunnel will bind (default: 0.0.0.0)')
    parser.add_argument('--local-port', type=int, default=12000, dest='lport',
                        help='set local port (default: 12000)')
    args = parser.parse_args()
    # User must always specify keyfile.
    if not args.keyfile:
        parser.print_help()
        print "[ERROR] No keyfile specified."
        return 1
    if not args.server:
        # User must specify TAP address when acting as a client.
        # The server will be 10.8.0.1 by default so the client can't
        # use the default.
        if not args.remote_address:
            parser.print_help()
            return 1
        try:
            client = OTPTunnel(
                args.taddr, args.tmask, args.tmtu, args.laddr,
                args.lport, args.remote_address, args.remote_port,
                args.keyfile, args.server)
        except (socket.error) as e:
            print >> sys.stderr, str(e)
            return 1
        client.run()
        return 0
    else:
        # We are in server mode.
        server = OTPTunnel(
            args.taddr, args.tmask, args.tmtu, args.laddr,
            args.lport, args.remote_address, args.remote_port,
            args.keyfile, args.server)
        server.run()
        return 0


if __name__ == '__main__':
    sys.exit(main())
