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
                 remote_port, keyfile, server):
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
        if server == False:
            self._key = Pad(keyfile, 0)
        else:
            self._key = Pad(keyfile, 1)
        self.running = False

    def run(self):
        self.running = True
        mtu = self._tmtu
        files = [self._tap, self._sock]
        to_tap = None
        to_sock = None
        while self.running:
            try:
                r, w, x = select.select(files, files, [])
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
                    #if addr[0] != self._remote_address or addr[1] != self._remote_port:
                    #    to_tap = ''  # drop packet
                if to_tap and self._tap in w:
                    # Begin write section of main loop. Only control packets and
                    # encoded packets received from socket should be processed
                    # here.
                    self._tap.write(to_tap)
                    to_tap = None
                if to_sock and self._sock in w:
                    # Packets read in from the TAP are encoded and written
                    # to the socket as bytes. The socket.sendto() function
                    # encapsulates the encoded payload with the appropriate
                    # Ethernet/IP/UDP headers.
                    to_sock = self._key.encode(to_sock)
                    self._sock.sendto(
                        to_sock, (self._remote_address, self._remote_port))
                    to_sock = None
            except (select.error, socket.error) as e:
                if e[0] == errno.EINTR:
                    continue
                sys.stderr.write(str(e))
                break
    
    def stop(self):
        self.running = False
