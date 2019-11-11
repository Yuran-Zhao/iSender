import socket
import struct
from Utils.utils import Str2Bytes


class UDP(object):

    def __init__(self, udp=None):
        if udp is None:
            return
        self.src_ip = socket.inet_aton(udp['src_ip'])
        self.dst_ip = socket.inet_aton(udp['dst_ip'])
        self.src_port = udp['src_port']
        self.dst_port = udp['dst_port']
        self.data = Str2Bytes(udp['data'])
        self.checksum = 0
        self.length = 8 + len(self.data)


    # calculate the check sum of header
    @staticmethod
    def Check_sum(packet):
        length = len(packet)
        num_final = ~((packet[0] << 8)+packet[1]) & 0xFFFF
        for i in range(2, length, 2):
            num_final = num_final + ~((packet[i] << 8)+packet[i+1]) & 0xFFFF
        return ~num_final & 0xFFFF

    # construct the whole UDP message
    def pack(self):
        packet_pHeader = struct.pack("!4s4sHHHHHH",
                                    self.src_ip,
                                    self.dst_ip,
                                    17,
                                    self.length,
                                    self.src_port,
                                    self.dst_port,
                                    self.length,
                                    0)
        packet_pHeader = packet_pHeader + self.data
        if len(self.data) % 2 != 0:
            self.checksum = self.Check_sum(packet_pHeader + str.encode('\x00'))
        else:
            self.checksum = self.Check_sum(packet_pHeader)
        packet = struct.pack("!HHHH",
                             self.src_port,
                             self.dst_port,
                             self.length,
                             self.checksum)
        packet = packet + self.data
        return packet

    def send(self):
        udpmsg = self.pack()
        socket_send = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        socket_send.sendto(udpmsg, (socket.inet_ntoa(self.dst_ip), self.dst_port))
        socket_send.close()

    # return the information showed in the log
    def detail(self):
        detail = {}
        detail['protocol'] = 'UDP'
        detail['source IP address'] = socket.inet_ntoa(self.src_ip)
        detail['destination IP address'] = socket.inet_ntoa(self.dst_ip)
        detail['source port'] = str(self.src_port)
        detail['destination port'] = str(self.dst_port)
        detail['checksum'] = '%#x' % self.checksum
        detail['data'] = bytes.decode(self.data)
        return detail
