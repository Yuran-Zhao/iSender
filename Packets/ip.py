import socket
import struct
from Utils.utils import Str2Bytes

# types of protocol
PROTOCOLDICT = {
    1: "ICMP",
    6: "TCP",
    17: "UDP"
}


class IP (object):
    def __init__(self, ipmsg=None):
        if ipmsg is None:
            return
        # the version is ipv4
        self.ipv = 4
        # default value of length is 20 bytes
        self.head_len = 5
        self.ser_type = ipmsg['type_of_service']
        self.id = ipmsg['identity']
        self.flag = ipmsg['flags']
        # the information about fragment
        self.frag_off = ipmsg['fragment_offsite']
        # time to live
        self.ttl = ipmsg['ttl']
        self.protoc = ipmsg['protocol']
        # in the beginning check sum is 0
        self.head_sum = 0
        # convert ip address to strings(4 bytes)
        self.src_ip = socket.inet_aton(ipmsg['source_ip'])
        self.dst_ip = socket.inet_aton(ipmsg['destination_ip'])
        self.src_port = ipmsg['source_port']
        self.dst_port = ipmsg['destination_port']

        self.option = Str2Bytes(ipmsg['option'])
        # if option exits
        if len(self.option) != 0:
            if len(self.option) % 4 == 0:
                self.head_len += int(len(self.option) / 4)
            else:
                # need to add '\x00'
                self.head_len += (int(len(self.option) / 4) + 1)
        else:
            self.option = str.encode('')

        if isinstance(ipmsg['data'], bytes):
            self.data = ipmsg['data']
        else:
            self.data = Str2Bytes(ipmsg['data'])
        self.total_len = (self.head_len * 4) + int(len(self.data))


    # calculate the check sum of header
    @staticmethod
    def Check_sum(header):
        length = len(header)
        flag = length % 2
        result = 0
        for i in range(0, length - flag, 2):
            result += (header[i] << 8) + header[i + 1]
        if flag:
            result += header[length - 1]
        while result >> 16:
            result = (result & 0xffff) + result >> 16
        result = (~result) & 0xffff
        return result

    # construct the whole ip message
    def pack(self):
        # ip_version and head_length compose 1 byte
        ipv_headlen = (self.ipv << 4) + self.head_len
        # flags and frag_offsite compose 2 bytes
        flag_offset = (self.flag << 13) + self.frag_off
        IPHeader = struct.pack("!BBHHHBBH4s4s",
                                ipv_headlen,
                                self.ser_type,
                                self.total_len,
                                self.id,
                                flag_offset,
                                self.ttl,
                                self.protoc,
                                self.head_sum,
                                self.src_ip,
                                self.dst_ip
                                )

        # if option exits in the information, need to add it to header
        # so we need to consider it when we calculate check_sum
        if self.option == str.encode(''):
            self.head_sum = self.Check_sum(IPHeader)
        else:
            self.head_sum = self.Check_sum(IPHeader + self.option)

        IPHeader = struct.pack("!BBHHHBBH4s4s",
                                ipv_headlen,
                                self.ser_type,
                                self.total_len,
                                self.id,
                                flag_offset,
                                self.ttl,
                                self.protoc,
                                self.head_sum,
                                self.src_ip,
                                self.dst_ip
                                )

        if self.option != str.encode(''):
            if len(self.option) % 4 == 0:
                IPHeader = IPHeader + self.option
            else:
                # if length is not a multiple of 4, add to some \x00
                IPHeader = IPHeader + self.option + (4 - (len(self.option) % 4)) * (str.encode('\x00'))

        # the whole message is composed of header and data
        IPmsg = IPHeader + self.data
        return IPmsg

    # send the constracted message
    def send(self):
        ipmsg = self.pack()
        # (HOST, PORT) represents the destination
        HOST = socket.inet_ntoa(self.dst_ip)
        PORT = self.dst_port
        socket_send = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        # use the IP header we construct
        socket_send.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        socket_send.sendto(ipmsg, (HOST, PORT))
        socket_send.close()

    # return the information showed in the log
    def detail(self):
        detail = {}
        detail['version'] = 'ipv4'
        detail['head length'] = str(self.head_len)
        detail['type of service'] = str(self.ser_type)
        detail['total length'] = str(self.total_len)
        detail['identification'] = str(self.id)
        detail['reserved'] = '0'
        detail['DF'] = str(self.flag / 2)
        detail['MF'] = str(self.flag % 2)
        detail['fragment offsite'] = str(self.frag_off)
        detail['time to live'] = str(self.ttl)
        detail['protocol'] = PROTOCOLDICT[self.protoc]
        detail['checksum'] = '%#x' % self.head_sum
        detail['source IP address'] = socket.inet_ntoa(self.src_ip)
        detail['destination IP address'] = socket.inet_ntoa(self.dst_ip)
        detail['source port'] = str(self.src_port)
        detail['destination port'] = str(self.dst_port)
        detail['option'] = bytes.decode(self.option)
        detail['data'] = bytes.decode(self.data)
        return detail
