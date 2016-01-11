from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor

class Sender(DatagramProtocol):

    def startProtocol(self): 
        print "Start Protocol"
        self.transport.write("INFO", ("127.0.0.1", 9999))

    def stopProtocol(self):
        print "Stop Protocol"

    def datagramReceived(self, data, (host, port)):
        print "received %r from %s:%d" % (data, host, port)
        reactor.stop()
        # self.transport.write(data, (host, port))

reactor.listenUDP(9998, Sender())
reactor.run()