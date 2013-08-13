import sys
import optparse
import socket
import select
import errno
import pytun
from scapy.all import *
from operator import xor

class TunnelServer(object):

    def __init__(self, taddr, tmask, tmtu, laddr, lport, raddr, rport):
        self._tap = pytun.TunTapDevice(flags=pytun.IFF_TAP|pytun.IFF_NO_PI)
        self._tap.addr = taddr
        self._tap.netmask = tmask
        self._tap.mtu = tmtu
        self._tap.up()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind((laddr, lport))
        self._raddr = raddr
        self._rport = rport

        with open('rand','r') as f:
            self._keypool = bytearray(f.read())

        self._global_key_offset = 0

    def run(self):
        mtu = self._tap.mtu
        r = [self._tap, self._sock]; w = []; x = []
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
                    if addr[0] != self._raddr or addr[1] != self._rport:
                        to_tap = '' # drop packet                    
                if self._tap in w:
                    self._tap.write(to_tap) 
                    to_tap = ''
                if self._sock in w:
                    # Encode entire 'to_sock' packet
                    to_sock = self.encode_pkt_from_tap(to_sock)
                    print "*****new to_sock*****"
                    print to_sock
                    self._sock.sendto(to_sock, (self._raddr, self._rport))
                    to_sock = ''
                r = []; w = []
                if to_tap:
                    w.append(self._tap)
                else:
                    r.append(self._sock)
                if to_sock:
                    w.append(self._sock)
                else:
                    r.append(self._tap)
            except (select.error, socket.error, pytun.Error), e:
                if e[0] == errno.EINTR:
                    continue
                print >> sys.stderr, str(e)
                break

    def encode_pkt_from_tap(self, pkt):
        self._global_key_offset = 0
        ether_pkt = Ether(pkt)

        print "*" * 40
        print "  Encoding packet received from TAP"
        print "*" * 40
        ether_pkt.display()
        print ""

        plaintext = bytearray(ether_pkt.original)
        ciphertext = bytearray()
        for i in plaintext:
            ciphertext.append(xor(i, self._keypool[self._global_key_offset]))
            self._global_key_offset += 1
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
        



def main():
    parser = optparse.OptionParser()
    parser.add_option('--tap-addr', dest='taddr',
            help='set tunnel local address')
    parser.add_option('--tap-netmask', default='255.255.255.0',dest='tmask',
            help='set tunnel netmask')
    parser.add_option('--tap-mtu', type='int', default=1500,dest='tmtu',
            help='set tunnel MTU')
    parser.add_option('--local-addr', default='0.0.0.0', dest='laddr',
            help='set local address [%default]')
    parser.add_option('--local-port', type='int', default=12000, dest='lport',
            help='set local port [%default]')
    parser.add_option('--remote-addr', dest='raddr',
            help='set remote address')
    parser.add_option('--remote-port', type='int', dest='rport',
            help='set remote port')
    opt, args = parser.parse_args()
    if not (opt.taddr and opt.raddr and opt.rport):
        parser.print_help()
        return 1
    try:
        server = TunnelServer(opt.taddr, opt.tmask, opt.tmtu, opt.laddr,
                opt.lport, opt.raddr, opt.rport)
    except (pytun.Error, socket.error), e:
        print >> sys.stderr, str(e)
        return 1
    server.run()
    return 0

if __name__ == '__main__':
    sys.exit(main())

