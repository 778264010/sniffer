from scapy.all import *
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QApplication, QMainWindow, QComboBox, QWidget, QTreeWidget, QVBoxLayout, QTreeWidgetItem, \
    QListWidget, QLabel, QHBoxLayout, QDialog, QPushButton
import sys

class SnifferWindow(QMainWindow):
    def __init__(self):
        super(SnifferWindow, self).__init__()
        self.setGeometry(200, 200, 500, 300)
        self.setWindowTitle("Network Sniffer")
        self.initUI()

    def initUI(self):
        self.counter = 0
        self.url_label = QtWidgets.QLabel(self)
        self.url_label.setText("URL:")
        self.url_label.move(10, 10)

        self.url_input = QtWidgets.QLineEdit(self)
        self.url_input.move(40, 10)
        self.url_input.resize(200, 30)

        self.iface_label = QtWidgets.QLabel(self)
        self.iface_label.setText("Interface:")
        self.iface_label.move(250, 10)

        self.iface_combo = QComboBox(self)
        self.iface_combo.addItems(get_if_list())
        self.iface_combo.move(310, 10)
        self.iface_combo.resize(100, 30)

        self.start_button = QtWidgets.QPushButton(self)
        self.start_button.setText("Start")
        self.start_button.move(10, 50)
        self.start_button.clicked.connect(self.start_sniffing)

        # self.output_text = QtWidgets.QPlainTextEdit(self)
        # self.output_text.setReadOnly(True)
        # self.output_text.resize(480, 200)
        # self.output_text.move(10, 90)

        self.packets_list = QListWidget(self)
        self.packets_list.resize(480,200)
        self.packets_list.move(10,90)


        self.show_data_button = QPushButton(self)
        self.show_data_button.setText("show_data_button")
        self.show_data_button.move(100, 50)
        self.show_data_button.clicked.connect(self.show_data)

        self.stop_button = QPushButton(self)
        self.stop_button.setText("stop_button")
        self.stop_button.move(190, 50)
        self.stop_button.clicked.connect(self.stop_sniffing)

        self.sniffer = None
        self.packets = []

    def start_sniffing(self):
        url = str(self.url_input.text())
        iface = str(self.iface_combo.currentText())
        if url:
            self.sniffer = AsyncSniffer(prn=self.handle_packet, filter=f"host {url}")
            # self.sniffer = AsyncSniffer(prn=self.handle_packet, filter="host " + url,iface=iface)
            self.sniffer.start()
            # 启动嗅探器
            # self.sniffer.start()
            # self.sniffer = sniff(filter="host " + url, iface=iface)
            # self.sniffer.start()
            # for packet in packets:
            #     self.packets_list.appendPlainText(str(packet.summary()))

    # 停止嗅探器
    def stop_sniffing(self):
        self.sniffer.stop()
    # 处理捕获的数据包
    def handle_packet(self, packet):
        self.packets.append(packet)
        self.counter += 1
        self.packets_list.addItem(str(self.counter))
        self.packets_list.addItem(str(packet))

    # 创建新窗口显示16进制数据信息
    def show_data(self):
        data_window = QDialog(self)
        data_window.setWindowTitle("16进制信息")
        data_layout = QVBoxLayout(data_window)

        # 显示数据信息
        data_widget = DataWindow(self.packets)
        data_layout.addWidget(data_widget)

        # 显示窗口
        data_window.exec_()

# 定义16进制数据窗口类
class DataWindow(QWidget):
    def __init__(self, packets):
        super().__init__()

        # 创建UI控件
        self.tree = QTreeWidget()

        # 填充数据包信息
        for packet in packets:
            self.add_packet(packet)

        # 设置UI布局
        vbox = QVBoxLayout()
        vbox.addWidget(self.tree)
        self.setLayout(vbox)

    def add_packet(self, packet):
        # 添加数据包节点
        packet_item = QTreeWidgetItem(self.tree, ["数据包", "", ""])
        # 获取根节点在QTreeWidget控件中的索引值
        index = self.tree.indexOfTopLevelItem(packet_item)
        # 设置节点的数字编号
        packet_item.setText(0, str(index + 1) + ".")
        self.add_layer(packet_item, packet)

    def add_layer(self, parent_item, packet):
        layer_name = packet.__class__.__name__
        layer_item = QTreeWidgetItem(parent_item, [layer_name, "", ""])
        layer_item.setText(0, hexdump(packet, dump=True))

def window():
    app = QApplication(sys.argv)
    win = SnifferWindow()
    win.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    window()