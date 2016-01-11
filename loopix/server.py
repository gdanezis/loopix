from binascii import hexlify

from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor

from format2 import setup, mix_operate

from petlib.pack import encode, decode

class Echo(DatagramProtocol):

    def __init__(self, port):
        self.port = port

        # Crypto Setup
        self.setup = setup()
        G, o, g, o_bytes = self.setup

        # Crypto keys
        self.y = o.random()
        self.ypub = self.y * g

    def startProtocol(self): 
        # Start Protocol
        self.ip = self.transport.getHost()

    def stopProtocol(self):
        print "Stop Protocol"

    def datagramReceived(self, data, (host, port)):

        # Deal with information requests
        if data[:4] == "INFO":
            self.do_INFO(data, (host, port))

        # Deal with routing requests
        if data[:4] == "ROUT":
            self.do_ROUT(data, (host, port))


    def do_INFO(self, data, (host, port)):
        print "do INFORMATION"
        hexkey = hexlify(self.ypub.export())
        resp = "RINF %s %s %s" % (self.ip.host, self.port, hexkey)

        # Respond
        self.transport.write(resp, (host, port))


    def do_ROUT(self, data, (host, port)):
        print "do ROUTING"
        msg = decode(data[4:])
        (xfrom, xto), next_msg = mix_operate(msg, (self.y, self.ypub, None), self.setup)



if __name__ == "__main__":
    port = 9999
    reactor.listenUDP(port, Echo(port))
    reactor.run()