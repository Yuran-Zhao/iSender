import socket
import struct


class TCP(object):
    def __init__(self, tcpmsg = None):
        if tcpmsg is None:
            return

        self.src_port = tcpmsg['source_port']
        self.dst_port = tcpmsg['destination_port']
        self.src_ip = socket.inet_aton(tcpmsg['source_ip'])
        self.dst_ip = socket.inet_aton(tcpmsg['destination_ip'])

        self.seq_num = tcpmsg['seq_number']

        # if it's a initial message, ack_num = 0
        if self.seq_num == 0:
            self.ack_num = 0
        else:
            self.ack_num = tcpmsg['ack_number']  # the sequence number ready to receive next time

        self.data_off = 5  # length of the TCP message
        self.reserved = 0

        self.urg = tcpmsg['urg']
        self.ack = tcpmsg['ack']
        self.psh = tcpmsg['psh']
        self.rst = tcpmsg['rst']
        self.syn = tcpmsg['syn']

        self.fin = tcpmsg['fin']

        self.win = tcpmsg['win']
        self.head_sum = 0
        # if urg not exits, the urgent_pointer is nonsense
        if self.urg == 0:
            self.urgent_p = 0
        else:
            self.urgent_p = tcpmsg['urgent_pointer']
        self.option = self.Str2Bytes(tcpmsg['option'])
        if len(self.option) != 0:
            if len(self.option) % 4 == 0:
                self.data_off += int(len(self.option) / 4)
            else:
                # need add to \x00
                self.data_off += (int(len(self.option) / 4) + 1)
        else:
            self.option = str.encode('')

        self.data = self.Str2Bytes(tcpmsg['data'])

    # convert HEX to int
    @staticmethod
    def Convert(character):
        if character == 'A' or character == 'a':
            return 10
        else:
            if character == 'B' or character == 'b':
                return 11
            else:
                if character == 'C' or character == 'c':
                    return 12
                else:
                    if character == 'D' or character == 'd':
                        return 13
                    else:
                        if character == 'E' or character == 'e':
                            return 14
                        else:
                            if character == 'F' or character == 'f':
                                return 15
                            else:
                                if '0' <= character <= '9':
                                    return int(character)

    # convert string to bytes
    def Str2Bytes(self, data):
        length = int(len(data) / 2)
        result = b''
        for i in range(length):
            substr = data[i * 2: (i + 1) * 2]
            num_1 = self.Convert(substr[0])
            num_2 = self.Convert(substr[1])
            num = num_1 * 16 + num_2
            result += struct.pack("!B", num)
        return result

    # calculate the check sum of header
    @staticmethod
    def Check_sum(data):
        length = len(data)
        flag = length % 2
        result = 0
        for i in range(0, length - flag, 2):
            result += (data[i] << 8) + data[i + 1]
        if flag:
            result += data[length - 1]
        while result >> 16:
            result = (result & 0xffff) + result >> 16
        result = (~result) & 0xffff
        return result

    # construct the whole TCP message
    def pack(self):
        # the length of header and some flags compose 2 bytes
        data_flags = (self.data_off << 12) + (self.urg << 5) + (self.ack << 4) + (self.psh << 3) + (self.rst << 2) + (self.syn << 1) + (self.fin)
        tcpheader = struct.pack("!HHLLHHHH",
                                self.src_port,
                                self.dst_port,
                                self.seq_num,
                                self.ack_num,
                                data_flags,
                                self.win,
                                self.head_sum,
                                self.urgent_p)
        if len(self.data) % 4 != 0:
            self.data += (4 - (len(self.data) % 4)) * (str.encode('\x00'))
        len_tcp = int(self.data_off) * 4 + int(len(self.data))
        implement = 6
        fake_header = struct.pack("!4s4sHH",
                                  self.src_ip,
                                  self.dst_ip,
                                  implement,
                                  len_tcp)
        if self.option == str.encode(''):
            self.head_sum = self.Check_sum(fake_header + tcpheader + self.data)
        else:
            self.head_sum = self.Check_sum(fake_header + tcpheader + self.option + self.data)
        tcpheader = struct.pack("!HHLLHHHH",
                                self.src_port,
                                self.dst_port,
                                self.seq_num,
                                self.ack_num,
                                data_flags,
                                self.win,
                                self.head_sum,
                                self.urgent_p)
        if self.option != str.encode(''):
            if len(self.option) % 4 == 0:
                tcpheader = tcpheader + self.option
            else:
                tcpheader = tcpheader + self.option + (4 - (len(self.option) % 4)) * (str.encode('\x00'))
        msg = tcpheader + self.data
        return msg

    def send(self):
        tcpmsg = self.pack()

        # (HOST, PORT) represents the destination
        HOST = socket.inet_ntoa(self.dst_ip)
        PORT = self.dst_port
        socket_send = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        socket_send.connect((HOST, PORT))
        socket_send.sendto(tcpmsg, (HOST, PORT))
        socket_send.close()

    # return the information showed in the log
    def detail(self):
        detail = {}
        detail['protocol'] = 'TCP'
        detail['source IP address'] = socket.inet_ntoa(self.src_ip)
        detail['destination IP address'] = socket.inet_ntoa(self.dst_ip)
        detail['source port'] = str(self.src_port)
        detail['destination port'] = str(self.dst_port)
        detail['sequence number'] = str(self.seq_num)
        detail['ACK number'] = str(self.ack_num)
        detail['head length'] = str(self.data_off)
        # detail['reserved'] = self.reserved
        detail['URG'] = str(self.urg)
        detail['ACK'] = str(self.ack)
        detail['PSH'] = str(self.psh)
        detail['RST'] = str(self.rst)
        detail['SYN'] = str(self.syn)
        detail['FIN'] = str(self.fin)
        detail['window size'] = str(self.win)
        detail['checksum'] = '%#x' % self.head_sum
        detail['urgent pointer'] = str(self.urgent_p)
        detail['option'] = bytes.decode(self.option)
        detail['data'] = bytes.decode(self.data)
        return detail
