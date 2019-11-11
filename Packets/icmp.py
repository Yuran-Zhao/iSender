import struct
import socket

# three types of ICMP message
TYPEDICT = {
    8: "request",
    0: "reply",
    11: "time out"
}


class ICMP(object):
    def __init__(self, icmpmsg=None):
        if icmpmsg is None:
            return

        self.type = icmpmsg['type']
        self.code = 0
        self.head_sum = 0
        # identity is a random number
        self.ident = icmpmsg['identity']
        self.seq_num = icmpmsg['sequence_number']
        self.src_ip = icmpmsg['source_ip']
        self.dst_ip = icmpmsg['destination_ip']
        # not need option
        self.option = None

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

    def pack(self):
        icmpheader = struct.pack("!BBHHH",
                                 self.type,
                                 self.code,
                                 self.head_sum,
                                 self.ident,
                                 self.seq_num)

        self.head_sum = self.Check_sum(icmpheader)

        icmpheader = struct.pack("!BBHHH",
                                 self.type,
                                 self.code,
                                 self.head_sum,
                                 self.ident,
                                 self.seq_num)
        icmpmsg = icmpheader

        return icmpmsg

    def send(self):
        icmpmsg = self.pack()
        service = socket.getprotobyname("icmp")
        socket_send = socket.socket(socket.AF_INET, socket.SOCK_RAW, service)
        socket_send.settimeout(5)
        target = self.dst_ip
        # target host may not reply the request message
        try:
            socket_send.sendto(icmpmsg, (target, 1))
            reply = socket_send.recvfrom(1024)
            if reply is not None:
                print(reply)
            socket_send.close()
        except:
            socket_send.close()

    # return the information showed in the log
    def detail(self):
        detail = {}
        detail['protocol'] = 'ICMP'
        detail['type'] = TYPEDICT[self.type]
        detail['source IP address'] = self.src_ip
        detail['destination IP address'] = self.dst_ip
        detail['source port'] = '--/--'
        detail['destination port'] = '--/--'
        detail['sequence number'] = str(self.seq_num)
        detail['checksum'] = '%#x' % self.head_sum
        return detail
