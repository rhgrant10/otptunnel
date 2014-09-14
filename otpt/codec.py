from contextlib import closing
import socket
import sys
import select
import errno
import pynetlinux
import threading


class Codec(threading.Thread):
    '''
    Codec uses a tap interface and a one-time pad to encode and decode packets.
    '''
    def __init__(self, tap, pad, laddr, raddr, mtu=32768):
        super(Codec, self).__init__()
        self._tap = tap
        self._pad = pad
        self._mtu = mtu
        self._local_address = laddr.rsplit(':', 1)
        self._remote_address = raddr.rsplit(':', 1)
        self._running = False
    
    def run(self):
        self._running = True
        with closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as sock:
            sock.bind(self._local_address)
            outgoing, incoming = None
            files = [self._tap, self._sock]
            while self._running:
                # Encode tap -> socket (outgoing)
                # Decode socket -> tap (incoming)
                try:
                    readables, writables, _ = select.select(files, files, [])
                    # Read if readables ready.
                    if self._tap in readables:
                        # read tap and encode it
                        outgoing = self._tap.read(self._mtu)
                        outgoing = self._pad.encode(outgoing)
                    if sock in readables:
                        # read socket and decode it
                        incoming, addr = sock.recvfrom(65535)
                        incoming = self._pad.decode(incoming)
                    # Write if content to write and writable is ready
                    if incoming and self._tap in writables:
                        self._tap.write(incoming)
                        incoming = None
                    if outgoing and sock in writables:
                        sock.sendto(outgoing, self._remote_address)
                        outgoing = None
                except (select.error, socket.error) as e:
                    if e[0] != errno.EINTR:
                        sys.stderr.write(str(e))
                        self._running = False
    
    def stop(self):
        self._running = False


class Server(Tunnel):
    def __init__(self, tap, pad, laddr, raddr, mtu):
        super(Server, self).__init__(self, tap, pad, laddr, raddr, mtu)
        self._pad.set_seek = 0
        

class Client(Tunnel):
    def __init__(self, tap, pad, laddr, raddr, mtu):
        super(Client, self).__init__(self, tap, pad, laddr, raddr, mtu)
        self._pad.set_seek = 1
