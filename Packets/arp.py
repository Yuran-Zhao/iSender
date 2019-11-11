import struct
import codecs
import socket

# some constant in the ARP header
HARDWARE_TYPE = 0x0001  # represents Internet
PROTOCOL_TYPE = 0x0800  # means ip address type
HARDWARE_LEN = 0x0006
PROTOCOL_LEN = 0x0004
OP_REQUEST = 0x0001
OP_REPLY = 0x0002

# two types of operations
OPDICT = {
    0x0001: "REQUEST",
    0x0002: "REPLY"
}

"""
as we use ARP to get the mac address of someone else,
in the Ether header, the destination address is BROADCAST
"""
BROADCAST = 'ff:ff:ff:ff:ff:ff'


class ARP(object):
    def __init__(self, arpmsg=None):
        if arpmsg is None:
            return
        self.op = arpmsg['op']  # operation
        # if only know the destination ip address
        # the destination mac address in ARP header should be '00:00:00:00:00:00'
        # and in Ether header the destination address should be 'ff:ff:ff:ff:ff:ff'
        # in other situation, they should be equal
        if arpmsg['destination_mac'] == '00:00:00:00:00:00':
            # convert mac address to bytes
            self.broadcast = self.parsemac(BROADCAST)
        else:
            self.broadcast = self.parsemac(arpmsg['destination_mac'])
        self.src_mac = self.parsemac(arpmsg['source_mac'])
        # convert ip address to strings (4bytes)
        self.src_ip = socket.inet_aton(arpmsg['source_ip'])
        self.dst_mac = self.parsemac(arpmsg['destination_mac'])
        self.dst_ip = socket.inet_aton(arpmsg['destination_ip'])
        self.interface = arpmsg['interface']

    # convert the mac address to bytes
    @staticmethod
    def parsemac(strings):
        strings = strings.replace(':', '')
        return codecs.decode(strings, 'hex')

    # convert the bytes representing mac address to format like 'xx:xx:xx:xx:xx:xx'
    @staticmethod
    def unparsemac(strings):
        n = bytes.decode(codecs.encode(strings, 'hex'))
        mac = ''
        for i in range(17):
            if (i+1) % 3 == 0:
                mac += ':'
            else:
                mac += n[i - int(i / 3)]
        return mac

    # construct a whole ARP message
    def pack(self):
        # constant
        Type_arp = 0x0806
        # ARP message needs an Ether header
        etherheader = struct.pack("!6s6sH",
                                  self.broadcast,
                                  self.src_mac,
                                  Type_arp)

        arpheader = struct.pack("!HHBBH6s4s6s4s",
                                HARDWARE_TYPE,
                                PROTOCOL_TYPE,
                                HARDWARE_LEN,
                                PROTOCOL_LEN,
                                self.op,
                                self.src_mac,
                                self.src_ip,
                                self.dst_mac,
                                self.dst_ip)
        return etherheader + arpheader

    def send(self):
        msg = self.pack()
        sock_send = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        sock_send.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock_send.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        # HOST is the interface through which this ARP message is sent
        HOST = self.interface
        sock_send.bind((HOST, 0))
        sock_send.send(msg)
        sock_send.close()

    # return the information showed in the log
    def detail(self):
        detail = {}
        detail['protocol'] = 'ARP'
        detail['operation'] = OPDICT[self.op]
        detail['source IP address'] = socket.inet_ntoa(self.src_ip)
        detail['destination IP address'] = socket.inet_ntoa(self.dst_ip)
        detail['source port'] = '--/--'
        detail['destination port'] = '--/--'
        detail['source MAC address'] = self.unparsemac(self.src_mac)
        detail['destination MAC address'] = self.unparsemac(self.dst_mac)
        return detail
