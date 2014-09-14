from .pad import Pad

import socket
import sys
import select
import errno
import pynetlinux
import threading


class Tunnel(threading.Thread):
    '''
    OTPTunnel initializes a TAP interface and instanciates an OTP object which
    is used to encode and decode packets throughout the main_loop.
    '''
    def __init__(self, taddr, tmask, tmtu, laddr, lport, remote_address,
                 remote_port, keyfile, keyoffset):
        super(Tunnel, self).__init__()
        self._tap = pynetlinux.tap.Tap()
        self._tap.ip = taddr
        self._tap.netmask = int(tmask)
        self._tap.up()
        self._tmtu = tmtu
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind((laddr, lport))
        self._remote_address = remote_address
        self._remote_port = remote_port
        self._key = Pad(keyfile, keyoffset)
        self.running = False

    @classmethod
    def Server(cls, taddr, tmask, tmtu, laddr, lport, raddr, rport, kfile):
        return cls(taddr, tmask, tmtu, laddr, lport, raddr, rport, kfile, 0)
        
    @classmethod
    def Client(cls, tarrd, tmask, tmtu, laddr, lport, raddr, rport, kfile):
        return cls(taddr, tmask, tmtu, laddr, lport, raddr, rport, kfile, 1)

    def run(self):
        self.running = True
        files = [self._tap, self._sock]
        to_tap = None
        to_sock = None
        while self.running:
            # Encode tap -> socket
            # Decode socket -> tap
            try:
                r, w, x = select.select(files, files, [])
                
                # Read if readables ready.
                if self._tap in r:
                    to_sock = self._tap.read(self._tmtu)
                    to_sock = self._key.encode(to_sock)     # encoding
                if self._sock in r:
                    to_tap, addr = self._sock.recvfrom(65535)
                    # Drop packets found on the socket if they are not from
                    # the server that we inteded to communicate with
                    #if addr[0] != self._remote_address or addr[1] != self._remote_port:
                    #    to_tap = ''  # drop packet
                    to_tap = self._key.decode(to_tap)   # decoding 
                
                # Write if content to write and writables ready
                if to_tap and self._tap in w:
                    self._tap.write(to_tap)
                    to_tap = None
                if to_sock and self._sock in w:
                    self._sock.sendto(
                        to_sock, (self._remote_address, self._remote_port))
                    to_sock = None
            except (select.error, socket.error) as e:
                if e[0] != errno.EINTR:
                    sys.stderr.write(str(e))
                    self.running = False
    
    def stop(self):
        self.running = False
