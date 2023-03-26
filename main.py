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


    def stop_sniffing(self):
        self.sniffer.stop()

    def handle_packet(self, packet):
        self.packets.append(packet)
        self.counter += 1
        self.packets_list.addItem(str(self.counter))
        self.packets_list.addItem(str(packet))


    def show_data(self):
        data_window = QDialog(self)
        data_window.setWindowTitle("information")
        data_layout = QVBoxLayout(data_window)

        data_widget = DataWindow(self.packets)
        data_layout.addWidget(data_widget)

        data_window.exec_()


class DataWindow(QWidget):
    def __init__(self, packets):
        super().__init__()

        self.tree = QTreeWidget()

        for packet in packets:
            self.add_packet(packet)

        vbox = QVBoxLayout()
        vbox.addWidget(self.tree)
        self.setLayout(vbox)

    def add_packet(self, packet):

        packet_item = QTreeWidgetItem(self.tree, ["packet", "", ""])

        index = self.tree.indexOfTopLevelItem(packet_item)

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