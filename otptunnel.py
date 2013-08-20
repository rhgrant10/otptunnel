#!/usr/bin/env python

import textwrap
import sys
import argparse
import socket
import select
import errno
import pytun
from operator import xor
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *


class TunnelServer(object):

    """
    This is the OTPTunnel server. It provides slightly different functionality
    than the TunnelClient class.
    """

    def __init__(self, taddr, tmask, tmtu, laddr, lport, remote_address, remote_port, server, keyfile, memory):
        self._tap = pytun.TunTapDevice(flags=pytun.IFF_TAP | pytun.IFF_NO_PI)
        self._tap.addr = taddr
        self._tap.netmask = tmask
        self._tap.mtu = tmtu
        self._tap.up()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind((laddr, lport))
        self._remote_address = remote_address
        self._remote_port = remote_port

        try:
            with open(keyfile, 'r') as f:
                self._keypool = bytearray(f.read())
        except:
            sys.exit('invalid keyfile specified')

        self._global_key_offset = 0

    def run(self):
        mtu = self._tap.mtu
        r = [self._tap, self._sock]
        w = []
        x = []
        to_tap = ''
        to_sock = ''
        while True:
            try:
                r, w, x = select.select(r, w, x)
                if self._tap in r:
                    to_sock = self._tap.read(mtu)
                    print "*****read to_sock*****"
                    print to_sock

                if self._sock in r:
                    to_tap, addr = self._sock.recvfrom(65535)
                    print "*****old TO_TAP*****"
                    print to_tap
                    to_tap = self.decode_pkt_from_socket(to_tap)
                    print "*****new TO_TAP*****"
                    print to_tap
                    # if addr[0] != self._remote_address or addr[1] != self._remote_port:
                    # to_tap = '' # drop packet
                if self._tap in w:
                    self._tap.write(to_tap)
                    to_tap = ''
                if self._sock in w:
                    # Encode entire 'to_sock' packet
                    to_sock = self.encode_pkt_from_tap(to_sock)
                    print "*****new to_sock*****"
                    print to_sock
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
            except (select.error, socket.error, pytun.Error) as e:
                if e[0] == errno.EINTR:
                    continue
                print >> sys.stderr, str(e)
                break

    def encode_pkt_from_tap(self, pkt):

        # Initialize the global offset to '0'. This is to be replaced with a local offset
        # once key-syncing is set up properly.
        #self._global_key_offset = 0

        # Take our packet bytestring and convert it to a real packet object.
        ether_pkt = Ether(pkt)

        # Pretty print the human-readable interpretation of the packet.
        print "*" * 40
        print "  Encoding packet received from TAP"
        print "*" * 40
        ether_pkt.display()
        print ""

        # 'plaintext' is the bytearray of the original packet
        plaintext = bytearray(ether_pkt.original)

        # Here we take a hash of the bytestring that was the original packet.
        # The hashlib comes from scapy.
        hashish = bytearray(hashlib.md5(ether_pkt.original).digest())

        # We append the bytes that represent the hash of the packet to the end
        # of the packet
        for i in hashish:
            plaintext.append(i)

        # Initialize the ciphertext to be an empty bytearray to be appended to
        # in our cipherloop
        ciphertext = bytearray()

        # Cipher loop. Iterate over the bytes in plaintext and xor with the
        # keybytes from the global offset.
        for i in plaintext:
            ciphertext.append(xor(i, self._keypool[self._global_key_offset]))
            self._global_key_offset += 1

        # After the original packet plus the 16 bytes of md5 hashish are XOR'ed with the keybytes,
        # The offset within the keybytes is appended as a 6-byte hex number (little-endian) to the
        # packet bytes to be returned
        "0x{0:012x}".format(offset)

        # Return
        return str(ciphertext)

    def decode_pkt_from_socket(self, pkt):
        self._global_key_offset = 0
        ether_pkt = Ether(pkt)

        print "-" * 40
        print "  Decoding packet received from Socket"
        print "-" * 40
        ether_pkt.display()
        print ""

        plaintext = bytearray(ether_pkt.original)
        ciphertext = bytearray()
        for i in plaintext:
            ciphertext.append(xor(i, self._keypool[self._global_key_offset]))
            self._global_key_offset += 1
        return str(ciphertext)

class OTPKey(object):
    def __init__(self, keyfile, initial_seek, memory):
        self._keypath = os.path.join(keyfile)
        self.fetch_block(keyfile, initial_seek, memory)
        self.

    def fetch_block(self, keyfile, initial_seek, memory):
        try:
            with open(keyfile, 'r') as f:
                f.seek(initial_seek)
                self._keypool = bytearray(f.read(memory))
        except:
            sys.exit('invalid keyfile specified')

class TunnelClient(object):

    def __init__(self, taddr, tmask, tmtu, laddr, lport, remote_address, remote_port, keyfile, server, memory):
        self._tap = pytun.TunTapDevice(flags=pytun.IFF_TAP | pytun.IFF_NO_PI)
        self._tap.addr = taddr
        self._tap.netmask = tmask
        self._tap.mtu = tmtu
        self._tap.up()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind((laddr, lport)) 
        self._remote_address = remote_address
        self._remote_port = remote_port
        self._ctrl_pkt_size_limit = tmtu
        self._memory = memory

        keygen = OTPKey(keyfile, 0, self._memory)

        

        # Here, the client must request from the server it's step value in the keypool.
        # Step value is the number of bytes to skip (or step) ahead in the keypool. It is
        # also the total number of participants in the OTP VPN. The
        # number will be tracked by the server as well. If there is only one server and
        # one client, the server will start at offset 0, stepping 2 bytes, and the client
        # will start at offset 1, stepping 2 bytes. This way, the key is effectively divided in half
        # because there are two participants. If a new client connects to the server and proves
        # that it has the same keypool, the server will notify all clients to increase stepping
        # by one. With 3 users (including the server), your pool is divided into thirds, with 4 users,
        # fourths, and so on. This way, all users can share a key and be certain that no portion
        # of it will be used more than once.
        self.initialize_connection()

    def initialize_connection(self):
        plain_initpkt = IP(dst=self._remote_address) / UDP(
            dport=self._remote_port / "init")
        encoded_initpkt = encode_control_pkt(plain_initpkt)
        mtu = self._tap.mtu
        r = [self._tap, self._sock]
        w = []
        x = []
        to_tap = ''
        to_sock = ''

        while True:
            try:
                r, w, x = select.select(r, w, x)
                # if self._tap in r:

                if self._sock in r:
                    to_tap, addr = self._sock.recvfrom(65535)
                    to_tap = self.decode_control_packet(to_tap)
                    print "*****packet from socket*****"
                    print to_tap
                    # if addr[0] != self._remote_address or addr[1] != self._remote_port:
                    # to_tap = '' # drop packet
                if self._tap in w:
                    self._tap.write(to_tap)
                    to_tap = ''
                if self._sock in w:
                    # Encode entire 'to_sock' packet
                    to_sock = self.encode_pkt_from_tap(to_sock)
                    print "*****new to_sock*****"
                    print to_sock
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
            except (select.error, socket.error, pytun.Error) as e:
                if e[0] == errno.EINTR:
                    continue
                print >> sys.stderr, str(e)
                break

    def encode_control_pkt(self, pkt):
        pktbytes = bytearray(str(pkt))

        ciphertext = bytearray()
        counter
        for i in pkybytes:
            ciphertext.append(xor(i, self._keypool[self._global_key_offset]))
            self._global_key_offset += 1
        return str(ciphertext)

    def decode_control_pkt(self, pkt):
        pktbytes = bytearray(str(pkt))

    def run(self):
        mtu = self._tap.mtu
        r = [self._tap, self._sock]
        w = []
        x = []
        to_tap = ''
        to_sock = ''

        while True:
            try:
                r, w, x = select.select(r, w, x)
                if self._tap in r:
                    to_sock = self._tap.read(mtu)
                    print "*****read to_sock*****"
                    print to_sock

                if self._sock in r:
                    to_tap, addr = self._sock.recvfrom(65535)
                    to_tap = self.decode_pkt_from_socket(to_tap)

                    print "*****new TO_TAP*****"
                    print to_tap
                    # if addr[0] != self._remote_address or addr[1] != self._remote_port:
                    # to_tap = '' # drop packet
                if self._tap in w:
                    self._tap.write(to_tap)
                    to_tap = ''
                if self._sock in w:
                    # Encode entire 'to_sock' packet
                    to_sock = self.encode_pkt_from_tap(to_sock)
                    print "*****new to_sock*****"
                    print to_sock
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
            except (select.error, socket.error, pytun.Error) as e:
                if e[0] == errno.EINTR:
                    continue
                print >> sys.stderr, str(e)
                break

    def encode_pkt_from_tap(self, pkt):

        # Initialize the global offset to '0'. This is to be replaced with a local offset
        # once key-syncing is set up properly.
        #self._global_key_offset = 0

        # Take our packet bytestring and convert it to a real packet object.
        ether_pkt = Ether(pkt)

        # Print the human-readable interpretation of the packet.

        print "[INFO] Encoding packet received from TAP: {0}".format(ether_pkt.summary())

        # 'plaintext' is the bytearray of the original packet
        plaintext = bytearray(ether_pkt.original)

        # Here we take a hash of the bytestring that was the original packet.
        # The hashlib comes from scapy.
        hashish = bytearray(hashlib.md5(str(ether_pkt).digest()))

        # We append the bytes that represent the hash of the packet to the end
        # of the packet
        for i in hashish:
            plaintext.append(i)

        # Initialize the ciphertext to be an empty bytearray to be appended to
        # in our cipherloop
        ciphertext = bytearray()

        # Cipher loop. Iterate over the bytes in plaintext and xor with the
        # keybytes from the global offset.
        for i in plaintext:
            ciphertext.append(xor(i, self._keypool[self._global_key_offset]))
            self._global_key_offset += self._step

        # After the original packet plus the 16 bytes of md5 hashish are XOR'ed with the keybytes,
        # The offset within the keybytes is appended as a 6-byte hex number (little-endian) to the
        # packet bytes to be returned
        "0x{0:012x}".format(offset)

        # Return
        return str(ciphertext)

    def decode_pkt_from_socket(self, pkt):
        # self._global_key_offset = 0
        ether_pkt = Ether(pkt)

        print "-" * 40
        print "  Decoding packet received from Socket"
        print "-" * 40
        ether_pkt.display()
        print ""

        plaintext = bytearray(ether_pkt.original)
        ciphertext = bytearray()
        for i in plaintext:
            ciphertext.append(xor(i, self._keypool[self._global_key_offset]))
            self._global_key_offset += 1
        return str(ciphertext)

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
    parser.add_argument('-S', '--server', action="store_true",
                        help="set server mode (default: client mode)")
    parser.add_argument('-K', dest='keyfile', help='file to be used as key')
    parser.add_argument('-A', dest='remote_address',
                        help='set remote server address')
    parser.add_argument('-P', type=int, dest='remote_port', default='12000',
                        help='set remote server port')
    parser.add_argument(
        '--tap-addr', type=str, dest='taddr', default='10.8.0.1',
        help='set tunnel local address (default: 10.8.0.1)')
    parser.add_argument('--tap-netmask', default='255.255.255.0', dest='tmask',
                        help='set tunnel netmask (default: 255.255.255.0)')
    parser.add_argument('--tap-mtu', type=int, default=32768, dest='tmtu',
                        help='set tunnel MTU (default: 32768)')
    parser.add_argument('--local-addr', default='0.0.0.0', dest='laddr',
                        help='address to which OTPTunnel will bind (default: 0.0.0.0)')
    parser.add_argument('--local-port', type=int, default=12000, dest='lport',
                        help='set local port (default: 12000)')
    parser.add_argument(
        '--memory', type=int, default=1073741824, dest='memory',
                        help='amount of memory to allocate for keystack '
                        'in bytes (default: 1073741824)')
    args = parser.parse_args()

    # User must always specify keyfile.
    if not args.keyfile:
        parser.print_help()
        print "[ERROR] No keyfile specified."
        return 1

    if not server:
        # User must specify TAP address when acting as a client.
        # The server will be 10.8.0.1 by default so the client can't
        # use the default.
        if not ((args.taddr == '10.8.0.1') and args.remote_address):
            parser.print_help()
            return 1

        try:
            client = TunnelClient(
                args.taddr, args.tmask, args.tmtu, args.laddr,
                args.lport, args.remote_address, args.remote_port, args.keyfile, args.server, args.memory)
        except (pytun.Error, socket.error) as e:
            print >> sys.stderr, str(e)
            return 1

        client.run()
        return 0
    else:
        # We are in server mode.
        try:
            server = TunnelServer(
                args.taddr, args.tmask, args.tmtu, args.laddr,
                args.lport, args.remote_address, args.remote_port, args.keyfile, args.server,args,memory)
        except (pytun.Error, socket.error) as e:
            print >> sys.stderr, str(e)
            return 1

        server.run()
        return 0

if __name__ == '__main__':
    sys.exit(main())

