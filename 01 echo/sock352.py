# This is the skeleton code of a cs 352 socket
# You must change the code in the pass statements to make the client and server work.

import socket as ip


class socket:

    def __init__(self):
        self.closed = False
        self.sock = ip.socket(ip.AF_INET, ip.SOCK_DGRAM)
    
    def socket(self):
        self.__init__() 

    def bind(self, address):
        return self.sock.bind(address)

    def sendto(self, buffer, address):
        return self.sock.sendto(buffer, address)

    def recvfrom(self, nbytes):
        return self.sock.recvfrom(nbytes)

    def close(self):
        if not self.closed:
            self.sock.close()
            self.closed = True
