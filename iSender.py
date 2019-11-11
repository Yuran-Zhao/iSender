import sys
import socket
import uuid
import os
import re
from PyQt5.QtWidgets import *
from PyQt5.QtWidgets import QApplication, QMainWindow
from PyQt5.QtCore import QStringListModel
from MainWindow.mainwindow import Ui_iSender
from Packets.ip import IP
from Packets.tcp import TCP
from Packets.udp import UDP
from Packets.arp import ARP
from Packets.icmp import ICMP
OP_REQUEST = 0x0001
OP_REPLY = 0x0002

class MyWindow(QMainWindow, Ui_iSender):
    # 界面初始话，包括各组件大小的设置、信号槽设置、以及默认值显示
    def __init__(self, parent=None):
        super(MyWindow, self).__init__(parent)
        self.setupUi(self)
        self.setWindowTitle('iSender')
        # 为各log记录窗口设置列宽
        self.log_widget.setColumnWidth(0, 140)
        self.log_widget.setColumnWidth(1, 205)
        self.log_widget.setColumnWidth(2, 205)
        self.log_widget.setColumnWidth(3, 160)
        self.log_widget.setColumnWidth(4, 160)
        self.ip_log.setColumnWidth(0, 130)
        self.ip_log.setColumnWidth(1, 140)
        self.ip_log.setColumnWidth(2, 120)
        self.ip_log.setColumnWidth(3, 125)
        self.tcp_log.setColumnWidth(0, 130)
        self.tcp_log.setColumnWidth(1, 140)
        self.tcp_log.setColumnWidth(2, 120)
        self.tcp_log.setColumnWidth(3, 125)
        self.udp_log.setColumnWidth(0, 130)
        self.udp_log.setColumnWidth(1, 140)
        self.udp_log.setColumnWidth(2, 120)
        self.udp_log.setColumnWidth(3, 125)
        self.arp_log.setColumnWidth(0, 110)
        self.arp_log.setColumnWidth(1, 120)
        self.arp_log.setColumnWidth(2, 140)
        self.arp_log.setColumnWidth(3, 140)
        self.icmp_log.setColumnWidth(0, 170)
        self.icmp_log.setColumnWidth(1, 180)
        self.icmp_log.setColumnWidth(2, 160)
        # 设置QTableWidget一次选中一行、不可编辑
        self.log_widget.setSelectionBehavior(QTableWidget.SelectRows)
        self.log_widget.setEditTriggers(QTableWidget.NoEditTriggers)
        self.ip_log.setSelectionBehavior(QTableWidget.SelectRows)
        self.ip_log.setEditTriggers(QTableWidget.NoEditTriggers)
        self.tcp_log.setSelectionBehavior(QTableWidget.SelectRows)
        self.tcp_log.setEditTriggers(QTableWidget.NoEditTriggers)
        self.udp_log.setSelectionBehavior(QTableWidget.SelectRows)
        self.udp_log.setEditTriggers(QTableWidget.NoEditTriggers)
        self.arp_log.setSelectionBehavior(QTableWidget.SelectRows)
        self.arp_log.setEditTriggers(QTableWidget.NoEditTriggers)
        self.icmp_log.setSelectionBehavior(QTableWidget.SelectRows)
        self.icmp_log.setEditTriggers(QTableWidget.NoEditTriggers)
        # 当QTableWidget中的行被单击时调用相应的成员函数以显示详细信息
        self.log_widget.cellClicked.connect(self.show_detail)
        self.ip_log.cellClicked.connect(self.show_ip_detail)
        self.tcp_log.cellClicked.connect(self.show_tcp_detail)
        self.udp_log.cellClicked.connect(self.show_udp_detail)
        self.arp_log.cellClicked.connect(self.show_arp_detail)
        self.icmp_log.cellClicked.connect(self.show_icmp_detail)
        # 当各send按钮被点击时调用相应的成员函数完成报文的发送
        self.ip_send.clicked.connect(self.ip_sender)
        self.tcp_send.clicked.connect(self.tcp_sender)
        self.udp_send.clicked.connect(self.udp_sender)
        self.arp_send.clicked.connect(self.arp_sender)
        self.icmp_send.clicked.connect(self.icmp_sender)
        # 当clear按钮或clear(all)被点击时调用相应的函数以清除某一行或全部记录
        self.clear_log.clicked.connect(self.log_clearer)
        self.clear_all_log.clicked.connect(self.all_log_clearer)
        self.clear_ip_log.clicked.connect(self.ip_log_clearer)
        self.clear_all_ip_log.clicked.connect(self.all_ip_log_clearer)
        self.clear_tcp_log.clicked.connect(self.tcp_log_clearer)
        self.clear_all_tcp_log.clicked.connect(self.all_tcp_log_clearer)
        self.clear_udp_log.clicked.connect(self.udp_log_clearer)
        self.clear_all_udp_log.clicked.connect(self.all_udp_log_clearer)
        self.clear_arp_log.clicked.connect(self.arp_log_clearer)
        self.clear_all_arp_log.clicked.connect(self.all_arp_log_clearer)
        self.clear_icmp_log.clicked.connect(self.icmp_log_clearer)
        self.clear_all_icmp_log.clicked.connect(self.all_icmp_log_clearer)
        # 或取本机的IP地址，将其作为各报文的默认源地址，并在相应的输入框中显示
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
            s.close()
        except:
            ip = ''
        self.ip_source_address.setText(ip)
        self.tcp_source_address.setText(ip)
        self.udp_source_address.setText(ip)
        self.arp_source_ip.setText(ip)
        self.icmp_source_address.setText(ip)
        # 获取本机的MAC地址，将其作为ARP报文源MAC地址的默认值，并将其显示到相应的输入框中
        mac = uuid.UUID(int=uuid.getnode()).hex[-12:]
        self.arp_source_mac.setText(":".join([mac[e:e + 2] for e in range(0, 11, 2)]))
        # 为各报文项设置默认值，并显示到相应的输入框中
        self.ip_time_to_live.setText('128')
        self.ip_type_of_service.setText('0')
        self.ip_source_port.setText('61234')
        self.ip_df.setText('1')
        self.ip_mf.setText('0')
        self.ip_offset.setText('0')
        self.ip_identification.setText('1')
        self.tcp_sequence_number.setText('0')
        self.tcp_ack_number.setText('0')
        self.tcp_urg.setText('0')
        self.tcp_urgent_pointer.setText('0')
        self.tcp_rst.setText('0')
        self.tcp_fin.setText('0')
        self.tcp_window_size.setText('1024')
        self.arp_interface.setText(os.listdir('/sys/class/net/')[0])
        self.arp_destination_mac.setText('00:00:00:00:00:00')
        self.icmp_code.setText('0')
        self.icmp_sequence_number.setText('1')
        self.icmp_identification.setText('1')
        self.ip_data.setPlaceholderText('请输入16进制的数据')
        self.tcp_data.setPlaceholderText('请输入16进制数据')
        self.udp_data.setPlaceholderText('请输入16进制数据')
        self.ip_option.setPlaceholderText('请输入16进制数据')
        self.tcp_option.setPlaceholderText('请输入16进制数据')
        # 为某些输入框设置叉号，点击后该输入框中的内容清空
        self.ip_source_address.setClearButtonEnabled(True)
        self.ip_destination_address.setClearButtonEnabled(True)
        self.ip_option.setClearButtonEnabled(True)
        self.ip_data.setClearButtonEnabled(True)
        self.tcp_source_address.setClearButtonEnabled(True)
        self.tcp_destination_address.setClearButtonEnabled(True)
        self.tcp_option.setClearButtonEnabled(True)
        self.tcp_data.setClearButtonEnabled(True)
        self.udp_source_address.setClearButtonEnabled(True)
        self.udp_destination_address.setClearButtonEnabled(True)
        self.udp_data.setClearButtonEnabled(True)
        self.arp_source_ip.setClearButtonEnabled(True)
        self.arp_destination_ip.setClearButtonEnabled(True)
        self.arp_source_mac.setClearButtonEnabled(True)
        self.arp_destination_mac.setClearButtonEnabled(True)
        self.icmp_source_address.setClearButtonEnabled(True)
        self.icmp_destination_address.setClearButtonEnabled(True)
        # 定义几个list用于分别储存全部历史报文的信息及各个协议报文的信息
        self.log_list = []
        self.ip_log_list = []
        self.tcp_log_list = []
        self.udp_log_list = []
        self.arp_log_list = []
        self.icmp_log_list = []

    # 在全部记录的QTableWidget中添加记录
    def add_log(self):
        self.clear_all_log.setText('Clear All(' + str(len(self.log_list)) + ')')
        row_count = self.log_widget.rowCount()
        self.log_widget.insertRow(row_count)
        self.log_widget.setItem(row_count, 0, QTableWidgetItem(self.log_list[row_count]["protocol"]))
        self.log_widget.setItem(row_count, 1, QTableWidgetItem(self.log_list[row_count]["source IP address"]))
        self.log_widget.setItem(row_count, 2, QTableWidgetItem(self.log_list[row_count]["destination IP address"]))
        self.log_widget.setItem(row_count, 3, QTableWidgetItem(self.log_list[row_count]["source port"]))
        self.log_widget.setItem(row_count, 4, QTableWidgetItem(self.log_list[row_count]["destination port"]))

    # 在IP报文记录的QTableWidget中添加记录
    def add_ip_log(self):
        self.clear_all_ip_log.setText('Clear All(' + str(len(self.ip_log_list)) + ')')
        row_count = self.ip_log.rowCount()
        self.ip_log.insertRow(row_count)
        self.ip_log.setItem(row_count, 0, QTableWidgetItem(self.ip_log_list[row_count]["source IP address"]))
        self.ip_log.setItem(row_count, 1, QTableWidgetItem(self.ip_log_list[row_count]["destination IP address"]))
        self.ip_log.setItem(row_count, 2, QTableWidgetItem(self.ip_log_list[row_count]["source port"]))
        self.ip_log.setItem(row_count, 3, QTableWidgetItem(self.ip_log_list[row_count]["destination port"]))

    # 在TCP报文记录的QTableWidget中添加记录
    def add_tcp_log(self):
        self.clear_all_tcp_log.setText('Clear All(' + str(len(self.tcp_log_list)) + ')')
        row_count = self.tcp_log.rowCount()
        self.tcp_log.insertRow(row_count)
        self.tcp_log.setItem(row_count, 0, QTableWidgetItem(self.tcp_log_list[row_count]["source IP address"]))
        self.tcp_log.setItem(row_count, 1, QTableWidgetItem(self.tcp_log_list[row_count]["destination IP address"]))
        self.tcp_log.setItem(row_count, 2, QTableWidgetItem(self.tcp_log_list[row_count]["source port"]))
        self.tcp_log.setItem(row_count, 3, QTableWidgetItem(self.tcp_log_list[row_count]["destination port"]))

    # 在UDP报文记录的QTableWidget中添加记录
    def add_udp_log(self):
        self.clear_all_udp_log.setText('Clear All(' + str(len(self.udp_log_list)) + ')')
        row_count = self.udp_log.rowCount()
        self.udp_log.insertRow(row_count)
        self.udp_log.setItem(row_count, 0, QTableWidgetItem(self.udp_log_list[row_count]["source IP address"]))
        self.udp_log.setItem(row_count, 1, QTableWidgetItem(self.udp_log_list[row_count]["destination IP address"]))
        self.udp_log.setItem(row_count, 2, QTableWidgetItem(self.udp_log_list[row_count]["source port"]))
        self.udp_log.setItem(row_count, 3, QTableWidgetItem(self.udp_log_list[row_count]["destination port"]))

    # 在ARP报文记录的QTableWidget中添加记录
    def add_arp_log(self):
        self.clear_all_arp_log.setText('Clear All(' + str(len(self.arp_log_list)) + ')')
        row_count = self.arp_log.rowCount()
        self.arp_log.insertRow(row_count)
        self.arp_log.setItem(row_count, 0, QTableWidgetItem(self.arp_log_list[row_count]["source IP address"]))
        self.arp_log.setItem(row_count, 1, QTableWidgetItem(self.arp_log_list[row_count]["destination IP address"]))
        self.arp_log.setItem(row_count, 2, QTableWidgetItem(self.arp_log_list[row_count]["source MAC address"]))
        self.arp_log.setItem(row_count, 3, QTableWidgetItem(self.arp_log_list[row_count]["destination MAC address"]))

    # 在ICMP报文记录的QTableWidget中添加记录
    def add_icmp_log(self):
        self.clear_all_icmp_log.setText('Clear All(' + str(len(self.icmp_log_list)) + ')')
        row_count = self.icmp_log.rowCount()
        self.icmp_log.insertRow(row_count)
        self.icmp_log.setItem(row_count, 0, QTableWidgetItem(self.icmp_log_list[row_count]["source IP address"]))
        self.icmp_log.setItem(row_count, 1, QTableWidgetItem(self.icmp_log_list[row_count]["destination IP address"]))
        self.icmp_log.setItem(row_count, 2, QTableWidgetItem(self.icmp_log_list[row_count]["type"]))

    # 当全部记录的QTableWidget的某一条记录被点击时，在下面的QListView中显示其详细信息
    def show_detail(self):
        selected = self.log_widget.currentIndex().row()
        key_list = self.log_list[selected].keys()
        information = []
        for i in key_list:
            information.append(i + ": " + self.log_list[selected][i])
        slm = QStringListModel()
        slm.setStringList(information)
        self.detail_list.setModel(slm)

    # 当IP报文记录的QTableWidget的某一条记录被点击时，在旁边的QListView中显示其详细信息
    def show_ip_detail(self):
        selected = self.ip_log.currentIndex().row()
        key_list = self.ip_log_list[selected].keys()
        information = []
        for i in key_list:
            information.append(i + ": " + self.ip_log_list[selected][i])
        slm = QStringListModel()
        slm.setStringList(information)
        self.ip_detail_list.setModel(slm)

    # 当TCP报文记录的QTableWidget的某一条记录被点击时，在旁边的QListView中显示其详细信息
    def show_tcp_detail(self):
        selected = self.tcp_log.currentIndex().row()
        key_list = self.tcp_log_list[selected].keys()
        information = []
        for i in key_list:
            information.append(i + ": " + self.tcp_log_list[selected][i])
        slm = QStringListModel()
        slm.setStringList(information)
        self.tcp_detail_list.setModel(slm)

    # 当UDP报文记录的QTableWidget的某一条记录被点击时，在旁边的QListView中显示其详细信息
    def show_udp_detail(self):
        selected = self.udp_log.currentIndex().row()
        key_list = self.udp_log_list[selected].keys()
        information = []
        for i in key_list:
            information.append(i + ": " + self.udp_log_list[selected][i])
        slm = QStringListModel()
        slm.setStringList(information)
        self.udp_detail_list.setModel(slm)

    # 当ARP报文记录的QTableWidget的某一条记录被点击时，在旁边的QListView中显示其详细信息
    def show_arp_detail(self):
        selected = self.arp_log.currentIndex().row()
        key_list = self.arp_log_list[selected].keys()
        information = []
        for i in key_list:
            information.append(i + ": " + self.arp_log_list[selected][i])
        slm = QStringListModel()
        slm.setStringList(information)
        self.arp_detail_list.setModel(slm)

    # 当ICMP报文记录的QTableWidget的某一条记录被点击时，在旁边的QListView中显示其详细信息
    def show_icmp_detail(self):
        selected = self.icmp_log.currentIndex().row()
        key_list = self.icmp_log_list[selected].keys()
        information = []
        for i in key_list:
            information.append(i + ": " + self.icmp_log_list[selected][i])
        slm = QStringListModel()
        slm.setStringList(information)
        self.icmp_detail_list.setModel(slm)

    # 当全部报文记录的QTableWidget的clear按钮被点击时，清除QTableWidget和log_list中的该条记录
    def log_clearer(self):
        selected = self.log_widget.currentIndex().row()
        self.log_widget.removeRow(selected)
        self.log_list = self.log_list[:selected] + self.log_list[selected+1:]
        self.clear_all_log.setText('Clear All('+str(len(self.log_list))+')')

    # 当全部报文记录的QTableWidget的Clear All按钮被点击时，清除QTableWidget和log_list中的全部记录
    def all_log_clearer(self):
        row_count = self.log_widget.rowCount()
        for i in range(0, row_count):
            self.log_widget.removeRow(0)
        self.log_list = []
        self.clear_all_log.setText('Clear All(0)')

    # 当IP报文记录的QTableWidget的clear按钮被点击时，清除QTableWidget和ip_log_list中的该条记录
    def ip_log_clearer(self):
        selected = self.ip_log.currentIndex().row()
        self.ip_log.removeRow(selected)
        self.ip_log_list = self.ip_log_list[:selected] + self.ip_log_list[selected + 1:]
        self.clear_all_ip_log.setText('Clear All(' + str(len(self.ip_log_list)) + ')')

    # 当IP报文记录的QTableWidget的Clear All按钮被点击时，清除QTableWidget和ip_log_list中的全部记录
    def all_ip_log_clearer(self):
        row_count = self.ip_log.rowCount()
        for i in range(0, row_count):
            self.ip_log.removeRow(0)
        self.ip_log_list = []
        self.clear_all_ip_log.setText('Clear All(0)')

    # 当TCP报文记录的QTableWidget的clear按钮被点击时，清除QTableWidget和tcp_log_list中的该条记录
    def tcp_log_clearer(self):
        selected = self.tcp_log.currentIndex().row()
        self.tcp_log.removeRow(selected)
        self.tcp_log_list = self.tcp_log_list[:selected] + self.tcp_log_list[selected + 1:]
        self.clear_all_tcp_log.setText('Clear All(' + str(len(self.tcp_log_list)) + ')')

    # 当TCP报文记录的QTableWidget的Clear All按钮被点击时，清除QTableWidget和tcp_log_list中的全部记录
    def all_tcp_log_clearer(self):
        row_count = self.tcp_log.rowCount()
        for i in range(0, row_count):
            self.tcp_log.removeRow(0)
        self.tcp_log_list = []
        self.clear_all_tcp_log.setText('Clear All(0)')

    # 当UDP报文记录的QTableWidget的clear按钮被点击时，清除QTableWidget和udp_log_list中的该条记录
    def udp_log_clearer(self):
        selected = self.udp_log.currentIndex().row()
        self.udp_log.removeRow(selected)
        self.udp_log_list = self.udp_log_list[:selected] + self.udp_log_list[selected + 1:]
        self.clear_all_udp_log.setText('Clear All(' + str(len(self.udp_log_list)) + ')')

    # 当UDP报文记录的QTableWidget的Clear All按钮被点击时，清除QTableWidget和tcp_log_list中的全部记录
    def all_udp_log_clearer(self):
        row_count = self.udp_log.rowCount()
        for i in range(0, row_count):
            self.udp_log.removeRow(0)
        self.udp_log_list = []
        self.clear_all_udp_log.setText('Clear All(0)')

    # 当ARP报文记录的QTableWidget的clear按钮被点击时，清除QTableWidget和arp_log_list中的该条记录
    def arp_log_clearer(self):
        selected = self.arp_log.currentIndex().row()
        self.arp_log.removeRow(selected)
        self.arp_log_list = self.arp_log_list[:selected] + self.arp_log_list[selected + 1:]
        self.clear_all_arp_log.setText('Clear All(' + str(len(self.arp_log_list)) + ')')

    # 当ARP报文记录的QTableWidget的Clear All按钮被点击时，清除QTableWidget和arp_log_list中的全部记录
    def all_arp_log_clearer(self):
        row_count = self.arp_log.rowCount()
        for i in range(0, row_count):
            self.arp_log.removeRow(0)
        self.arp_log_list = []
        self.clear_all_arp_log.setText('Clear All(0)')

    # 当ICMP报文记录的QTableWidget的clear按钮被点击时，清除QTableWidget和icmp_log_list中的该条记录
    def icmp_log_clearer(self):
        selected = self.icmp_log.currentIndex().row()
        self.icmp_log.removeRow(selected)
        self.icmp_log_list = self.icmp_log_list[:selected] + self.icmp_log_list[selected + 1:]
        self.clear_all_icmp_log.setText('Clear All(' + str(len(self.icmp_log_list)) + ')')

    # 当ICMP报文记录的QTableWidget的Clear All按钮被点击时，清除QTableWidget和arp_log_list中的全部记录
    def all_icmp_log_clearer(self):
        row_count = self.icmp_log.rowCount()
        for i in range(0, row_count):
            self.icmp_log.removeRow(0)
        self.icmp_log_list = []
        self.clear_all_icmp_log.setText('Clear All(0)')

    # 获取用户输入的信息，构造IP报文并发送和添加记录
    def ip_sender(self):
        ipConfig = {}
        ptcl = {'TCP': 6, 'UDP': 17, 'ICMP': 1}
        hex_num = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
                   'a', 'b', 'c', 'd', 'e', 'f','A', 'B', 'C', 'D', 'E', 'F']
        if self.ip_type_of_service.text() == "":
            QMessageBox.critical(self, 'error', 'Type of Service should be specified!')
            return
        else:
            ipConfig["type_of_service"] = int(self.ip_type_of_service.text())

        if self.ip_identification.text() == "":
            QMessageBox.critical(self, 'error', 'Identification should be specified!')
            return
        else:
            ipConfig['identity'] = int(self.ip_identification.text())

        if self.ip_df.text() == "" or self.ip_mf.text() == "":
            QMessageBox.critical(self, 'error', 'DF and MF should be specified!')
            return
        else:
            if int(self.ip_df.text()) != 1 and int(self.ip_df.text()) != 0:
                QMessageBox.critical(self, 'error', 'DF should be either 0 or 1')
                return
            if int(self.ip_mf.text()) != 1 and int(self.ip_mf.text()) != 0:
                QMessageBox.critical(self, 'error', 'MF should be either 0 or 1')
                return
            ipConfig['flags'] = int(self.ip_df.text()) * 2 + int(self.ip_mf.text())

        if self.ip_offset.text() == "":
            QMessageBox.critical(self, 'error', 'Offset should be specified!')
            return
        else:
            ipConfig['fragment_offsite'] = int(self.ip_offset.text())

        if self.ip_time_to_live.text() == "":
            QMessageBox.critical(self, 'error', 'Time to live should be specified!')
            return
        else:
            ipConfig['ttl'] = int(self.ip_time_to_live.text())

        ipConfig['protocol'] = ptcl[self.ip_protocol.currentText()]

        if self.ip_source_address.text() == "":
            QMessageBox.critical(self, 'error', 'Source Address should be specified!')
            return
        else:
            ip_list = self.ip_source_address.text().split('.')
            if len(ip_list) != 4:
                QMessageBox.critical(self, 'error in Source Address', 'There should be 4 integers divided by "." ')
                return
            for i in range(0, 4):
                if int(ip_list[i])>255 or int(ip_list[i])<0:
                    QMessageBox.critical(self, 'error  Source Address', 'Each integer should be in [0, 255] ')
                    return
            ipConfig['source_ip'] = self.ip_source_address.text()

        if self.ip_destination_address == "":
            QMessageBox.critical(self, 'error', 'Destination Address should be specified!')
            return
        else:
            ip_list = self.ip_destination_address.text().split('.')
            if len(ip_list) != 4:
                QMessageBox.critical(self, 'error in Destination Address', 'There should be 4 integers divided by "." ')
                return
            for i in range(0, 4):
                if int(ip_list[i]) > 255 or int(ip_list[i]) < 0:
                    QMessageBox.critical(self, 'error in Destination Address', 'Each integer should be in [0, 255] ')
                    return
            ipConfig['destination_ip'] = self.ip_destination_address.text()

        if self.ip_destination_port.text() == "":
            QMessageBox.critical(self, 'error', 'Destination Port should be specified!')
            return
        else:
            if int(self.ip_destination_port.text())>65535 or int(self.ip_destination_port.text())<0:
                QMessageBox.critical(self, 'error', 'Destination Port should be in [0, 65535]')
                return
            ipConfig['destination_port'] = int(self.ip_destination_port.text())

        if self.ip_source_port.text() == "":
            QMessageBox.critical(self, 'error', 'Source Port should be specified!')
            return
        else:
            if int(self.ip_source_port.text())>65535 or int(self.ip_source_port.text())<0:
                QMessageBox.critical(self, 'error', 'Source Port should be in [0, 65535]')
                return
            ipConfig['source_port'] = int(self.ip_source_port.text())

        if len(self.ip_option.text().replace(' ',''))%2 != 0:
            QMessageBox.critical(self, 'error in Option', 'The number of HEX should be even!')
            return
        else:
            option = self.ip_option.text().replace(' ','')
            for i in range(0, len(option)):
                if option[i] not in hex_num:
                    QMessageBox.critical(self, 'error in Option', 'The input should be HEX numbers!')
                    return
            ipConfig['option'] = option

        if len(self.ip_data.text().replace(' ',''))%2 != 0:
            QMessageBox.critical(self, 'error in Data', 'The number of HEX should be even!')
            return
        else:
            data = self.ip_data.text().replace(' ', '')
            for i in range(0, len(data)):
                if data[i] not in hex_num:
                    QMessageBox.critical(self, 'error in Data', 'The input should be HEX numbers!')
                    return
            ipConfig['data'] = data

        self.ip_data.setText(re.sub(r"(?<=\w)(?=(?:\w\w)+$)", " ", self.ip_data.text()))
        self.ip_option.setText(re.sub(r"(?<=\w)(?=(?:\w\w)+$)", " ", self.ip_option.text()))
        ip_packet = IP(ipConfig)
        detail = ip_packet.detail()
        self.ip_log_list.append(detail)
        self.add_ip_log()
        self.log_list.append(detail)
        self.add_log()
        ip_packet.send()

    # 获取用户输入的信息，构造TCP报文并发送和添加记录
    def tcp_sender(self):
        tcpConfig = {}
        hex_num = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
                   'a', 'b', 'c', 'd', 'e', 'f', 'A', 'B', 'C', 'D', 'E', 'F']
        if self.tcp_source_port.text() == "":
            QMessageBox.critical(self, 'error', 'Source Port should be specified!')
            return
        else:
            if int(self.tcp_source_port.text())>65535 or int(self.tcp_source_port.text())<0:
                QMessageBox.critical(self, 'error', 'Source Port should be in [0, 65535]')
                return
            tcpConfig['source_port'] = int(self.tcp_source_port.text())

        if self.tcp_destination_port.text() == "":
            QMessageBox.critical(self, 'error', 'Destination Port should be specified!')
            return
        else:
            if int(self.tcp_destination_port.text())>65535 or int(self.tcp_destination_port.text())<0:
                QMessageBox.critical(self, 'error', 'Destinaion Port should be in [0, 65535]')
                return
            tcpConfig['destination_port'] = int(self.tcp_destination_port.text())

        if self.tcp_sequence_number.text() == "":
            QMessageBox.critical(self, 'error', 'Sequence Number should be specified!')
            return
        else:
            tcpConfig['seq_number'] = int(self.tcp_sequence_number.text())

        if self.tcp_urg.text() == "":
            QMessageBox.critical(self, 'error', 'URG should be specified!')
            return
        else:
            if int(self.tcp_urg.text()) != 1 and int(self.tcp_urg.text()) != 0:
                QMessageBox.critical(self, 'error', 'URG should be either 0 or 1')
                return
            tcpConfig['urg'] = int(self.tcp_urg.text())

        if self.tcp_ack.text() == "":
            QMessageBox.critical(self, 'error', 'ACK should be specified!')
            return
        else:
            if int(self.tcp_ack.text()) != 1 and int(self.tcp_ack.text()) != 0:
                QMessageBox.critical(self, 'error', 'ACK should be either 0 or 1')
                return
            tcpConfig['ack'] = int(self.tcp_ack.text())  # TCP 规定，在连接建立后所有传送的报文段都必须把 ACK 设置为 1

        if self.tcp_psh.text() == "":
            QMessageBox.critical(self, 'error', 'PSH should be specified!')
            return
        else:
            if int(self.tcp_psh.text()) != 1 and int(self.tcp_psh.text()) != 0:
                QMessageBox.critical(self, 'error', 'PSH should be either 0 or 1')
                return
            tcpConfig['psh'] = int(self.tcp_psh.text())

        if self.tcp_rst.text() == "":
            QMessageBox.critical(self, 'error', 'RST should be specified!')
            return
        else:
            if int(self.tcp_rst.text()) != 1 and int(self.tcp_rst.text()) != 0:
                QMessageBox.critical(self, 'error', 'RST should be either 0 or 1')
                return
            tcpConfig['rst'] = int(self.tcp_rst.text())

        if self.tcp_syn.text() == "":
            QMessageBox.critical(self, 'error', 'SYN should be specified!')
            return
        else:
            if int(self.tcp_syn.text()) != 1 and int(self.tcp_syn.text()) != 0:
                QMessageBox.critical(self, 'error', 'SYN should be either 0 or 1')
                return
            tcpConfig['syn'] = int(self.tcp_syn.text())

        if self.tcp_fin.text() == "":
            QMessageBox.critical(self, 'error', 'FIN should be specified!')
            return
        else:
            if int(self.tcp_fin.text()) != 1 and int(self.tcp_fin.text()) != 0:
                QMessageBox.critical(self, 'error', 'FIN should be either 0 or 1')
                return
            tcpConfig['fin'] = int(self.tcp_fin.text())

        if self.tcp_window_size.text() == "":
            QMessageBox.critical(self, 'error', 'Window Size should be specified!')
            return
        else:
            tcpConfig['win'] = int(self.tcp_window_size.text())

        if self.tcp_urgent_pointer.text() == "":
            QMessageBox.critical(self, 'error', 'Urgent Pointer should be specified!')
            return
        else:
            tcpConfig['urgent_pointer'] = int(self.tcp_urgent_pointer.text())

        if len(self.tcp_option.text().replace(' ',''))%2 != 0:
            QMessageBox.critical(self, 'error in Option', 'The number of HEX should be even!')
            return
        else:
            option = self.tcp_option.text().replace(' ', '')
            for i in range(0, len(option)):
                if option[i] not in hex_num:
                    QMessageBox.critical(self, 'error in Option', 'The input should be HEX numbers!')
                    return
            tcpConfig['option'] = option

        if len(self.tcp_data.text().replace(' ',''))%2 != 0:
            QMessageBox.critical(self, 'error in Data', 'The number of HEX should be even!')
            return
        else:
            data = self.tcp_data.text().replace(' ', '')
            for i in range(0, len(data)):
                if data[i] not in hex_num:
                    QMessageBox.critical(self, 'error in Data', 'The input should be HEX numbers!')
                    return
            tcpConfig['data'] = data

        if self.tcp_source_address.text() == "":
            QMessageBox.critical(self, 'error', 'Source Address should be specified!')
            return
        else:
            ip_list = self.tcp_source_address.text().split('.')
            if len(ip_list) != 4:
                QMessageBox.critical(self, 'error in Source Address', 'There should be 4 integers divided by "." ')
                return
            for i in range(0, 4):
                if int(ip_list[i]) > 255 or int(ip_list[i]) < 0:
                    QMessageBox.critical(self, 'error in Source Address', 'Each integer should be in [0, 255] ')
                    return
            tcpConfig['source_ip'] = self.tcp_source_address.text()

        if self.tcp_destination_address.text() == "":
            QMessageBox.critical(self, 'error', 'Destination Address should be specified!')
            return
        else:
            ip_list = self.tcp_destination_address.text().split('.')
            if len(ip_list) != 4:
                QMessageBox.critical(self, 'error in Destination Address', 'There should be 4 integers divided by "." ')
                return
            for i in range(0, 4):
                if int(ip_list[i]) > 255 or int(ip_list[i]) < 0:
                    QMessageBox.critical(self, 'error in Destination Address', 'Each integer should be in [0, 255] ')
                    return
            tcpConfig['destination_ip'] = self.tcp_destination_address.text()

        self.tcp_data.setText(re.sub(r"(?<=\w)(?=(?:\w\w)+$)", " ", self.tcp_data.text()))
        self.tcp_option.setText(re.sub(r"(?<=\w)(?=(?:\w\w)+$)", " ", self.tcp_option.text()))
        tcp_packet = TCP(tcpConfig)
        detail = tcp_packet.detail()
        self.tcp_log_list.append(detail)
        self.add_tcp_log()
        self.log_list.append(detail)
        self.add_log()
        tcp_packet.send()

    # 获取用户输入的信息，构造UDP报文并发送和添加记录
    def udp_sender(self):
        udpConfig = {}
        hex_num = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
                   'a', 'b', 'c', 'd', 'e', 'f', 'A', 'B', 'C', 'D', 'E', 'F']
        if self.udp_source_address.text() == "":
            QMessageBox.critical(self, 'error', 'Destination Address should be specified!')
            return
        else:
            ip_list = self.udp_source_address.text().split('.')
            if len(ip_list) != 4:
                QMessageBox.critical(self, 'error in Source Address', 'There should be 4 integers divided by "." ')
                return
            for i in range(0, 4):
                if int(ip_list[i]) > 255 or int(ip_list[i]) < 0:
                    QMessageBox.critical(self, 'error in Source', 'Each integer should be in [0, 255] ')
                    return
            udpConfig['src_ip'] = self.udp_source_address.text()

        if self.udp_destination_address.text() == "":
            QMessageBox.critical(self, 'error', 'Destination Address should be specified!')
            return
        else:
            ip_list = self.udp_destination_address.text().split('.')
            if len(ip_list) != 4:
                QMessageBox.critical(self, 'error in Destination Address', 'There should be 4 integers divided by "." ')
                return
            for i in range(0, 4):
                if int(ip_list[i]) > 255 or int(ip_list[i]) < 0:
                    QMessageBox.critical(self, 'error in Destination Address', 'Each integer should be in [0, 255] ')
                    return
            udpConfig['dst_ip'] = self.udp_destination_address.text()

        if self.udp_source_port.text() == "":
            QMessageBox.critical(self, 'error', 'Destination Address should be specified!')
            return
        else:
            if int(self.udp_destination_port.text())>65535 or int(self.udp_destination_port.text())<0:
                QMessageBox.critical(self, 'error', 'Source Port should be in [0, 65535]')
                return
            udpConfig['src_port'] = int(self.udp_source_port.text())

        if self.udp_destination_port.text() == "":
            QMessageBox.critical(self, 'error', 'Destination Address should be specified!')
            return
        else:
            if int(self.udp_destination_port.text())>65535 or int(self.udp_destination_port.text())<0:
                QMessageBox.critical(self, 'error', 'Destinaion Port should be in [0, 65535]')
                return
            udpConfig['dst_port'] = int(self.udp_destination_port.text())

        if len(self.udp_data.text().replace(' ',''))%2 != 0:
            QMessageBox.critical(self, 'error in Data', 'The number of HEX should be even!')
            return
        else:
            data = self.udp_data.text().replace(' ', '')
            for i in range(0, len(data)):
                if data[i] not in hex_num:
                    QMessageBox.critical(self, 'error in Data', 'The input should be HEX numbers!')
                    return
            udpConfig['data'] = data
        self.udp_data.setText(re.sub(r"(?<=\w)(?=(?:\w\w)+$)", " ", self.udp_data.text()))
        udp_packet = UDP(udpConfig)
        detail = udp_packet.detail()
        self.udp_log_list.append(detail)
        self.add_udp_log()
        self.log_list.append(detail)
        self.add_log()
        udp_packet.send()

    # 获取用户输入的信息，构造ARP报文并发送和添加记录
    def arp_sender(self):
        op_dict = {'request': OP_REQUEST, 'reply': OP_REPLY}
        hex_num = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
                   'A', 'B', 'C', 'D', 'E', 'F']
        arpConfig = {}

        arpConfig["op"] = op_dict[self.arp_operation_type.currentText()]
        if self.arp_interface.text() == '':
            QMessageBox.critical(self, 'error', 'Interface should be specified!')
            return
        else:
            arpConfig["interface"] = self.arp_interface.text()

        if self.arp_source_mac.text() == '':
            QMessageBox.critical(self, 'error', 'Source MAC Address should be specified!')
            return
        else:
            mac_list = self.arp_source_mac.text().split(':')
            if len(mac_list) != 6:
                QMessageBox.critical(self, 'error in Source MAC Address', 'There should be 6 HEX divided by ":" ')
                return
            for i in range(0, 6):
                if len(mac_list[i]) != 2:
                    QMessageBox.critical(self, 'error in Source MAC Address',
                                         'There should be two digits in each HEX number!')
                    return
                for j in range(0, 2):
                    if mac_list[i][j] not in hex_num:
                        QMessageBox.critical(self, 'error in Source MAC Address',
                                             'Wrong HEX digits. Should be 0-9 or a-f or A-F ')
                        return
            arpConfig["source_mac"] = self.arp_source_mac.text()

        if self.arp_source_ip.text() == '':
            QMessageBox.critical(self, 'error', 'Source IP Address should be specified!')
            return
        else:
            ip_list = self.arp_source_ip.text().split('.')
            if len(ip_list) != 4:
                QMessageBox.critical(self, 'error in Source IP Address', 'There should be 4 integers divided by "." ')
                return
            for i in range(0, 4):
                if int(ip_list[i]) > 255 or int(ip_list[i]) < 0:
                    QMessageBox.critical(self, 'error in Source IP Address',
                                         'Each integer should be in [0, 255] ')
                    return
            arpConfig["source_ip"] = self.arp_source_ip.text()

        if self.arp_destination_mac.text() == '':
            QMessageBox.critical(self, 'error', 'Destination MAC Address should be specified!')
            return
        else:
            mac_list = self.arp_destination_mac.text().split(':')
            if len(mac_list) != 6:
                QMessageBox.critical(self, 'error in Destination MAC Address', 'There should be 6 HEX divided by ":" ')
                return
            for i in range(0, 6):
                if len(mac_list[i]) != 2:
                    QMessageBox.critical(self, 'error in Destination MAC Address',
                                         'There should be two digits in each HEX number!')
                    return
                for j in range(0, 2):
                    if mac_list[i][j] not in hex_num:
                        QMessageBox.critical(self, 'error in Destination MAC Address',
                                             'Wrong HEX digits. Should be 0-9 or a-f or A-F ')
                        return
            arpConfig["destination_mac"] = self.arp_destination_mac.text()

        if self.arp_destination_ip.text() == '':
            QMessageBox.critical(self, 'error', 'Destination IP Address should be specified!')
            return
        else:
            ip_list = self.arp_destination_ip.text().split('.')
            if len(ip_list) != 4:
                QMessageBox.critical(self, 'error in Destination IP Address',
                                     'There should be 4 integers divided by "." ')
                return
            for i in range(0, 4):
                if int(ip_list[i]) > 255 or int(ip_list[i]) < 0:
                    QMessageBox.critical(self, 'error in Destination IP Address',
                                         'Each integer should be in [0, 255] ')
                    return
            arpConfig["destination_ip"] = self.arp_destination_ip.text()
        arp_packet = ARP(arpConfig)
        detail = arp_packet.detail()
        self.arp_log_list.append(detail)
        self.add_arp_log()
        self.log_list.append(detail)
        self.add_log()
        arp_packet.send()

    # 获取用户输入的信息，构造ICMP报文并发送和添加记录
    def icmp_sender(self):
        type_dict = {'request': 8, 'reply': 0, 'time out': 11}
        icmpConfig = {}

        icmpConfig["type"] = type_dict[self.icmp_type.currentText()]  # 0:ping应答；8:ping请求；11：超时
        if self.icmp_code.text() == '':
            QMessageBox.critical(self, 'error', 'Code should be specified!')
            return
        else:
            icmpConfig["code"] = int(self.icmp_code.text())

        if self.icmp_identification.text() == '':
            QMessageBox.critical(self, 'error', 'Identification should be specified!')
            return
        else:
            icmpConfig["identity"] = int(self.icmp_identification.text())

        if self.icmp_sequence_number.text() == '':
            QMessageBox.critical(self, 'error', 'Sequence Number should be specified!')
            return
        else:
            icmpConfig["sequence_number"] = int(self.icmp_sequence_number.text())

        if self.icmp_source_address.text() == '':
            QMessageBox.critical(self, 'error', 'Source IP Address should be specified!')
            return
        else:
            ip_list = self.icmp_source_address.text().split('.')
            if len(ip_list) != 4:
                QMessageBox.critical(self, 'error in Source Address', 'There should be 4 integers divided by "." ')
                return
            for i in range(0, 4):
                if int(ip_list[i]) > 255 or int(ip_list[i]) < 0:
                    QMessageBox.critical(self, 'error in Source Address', 'Each integer should be in [0, 255] ')
                    return
            icmpConfig["source_ip"] = self.icmp_source_address.text()

        if self.icmp_destination_address.text() == '':
            QMessageBox.critical(self, 'error', 'Destination IP Address should be specified!')
            return
        else:
            ip_list = self.icmp_destination_address.text().split('.')
            if len(ip_list) != 4:
                QMessageBox.critical(self, 'error in Destination Address', 'There should be 4 integers divided by "." ')
                return
            for i in range(0, 4):
                if int(ip_list[i]) > 255 or int(ip_list[i]) < 0:
                    QMessageBox.critical(self, 'error in Destination Address', 'Each integer should be in [0, 255] ')
                    return
            icmpConfig["destination_ip"] = self.icmp_destination_address.text()
        icmp_packet = ICMP(icmpConfig)
        detail = icmp_packet.detail()
        self.icmp_log_list.append(detail)
        self.add_icmp_log()
        self.log_list.append(detail)
        self.add_log()
        if not icmp_packet.send():
            QMessageBox.critical(self, 'Time out!', 'Reply not received!')


if __name__ == '__main__':
    app = QApplication(sys.argv)
    myWin = MyWindow()  # 创建一个MyWindow的实例
    myWin.show()  # 显示窗口
    sys.exit(app.exec_())
