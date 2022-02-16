from msilib.schema import Error
import threading

from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from MainWindow import *

import sys
import os
from datetime import datetime

import os,time,hashlib,wmi,pythoncom
from subprocess import check_output, CalledProcessError
from dB_init import create_server_connection, read_query


class MainWindow(QDialog):
    def __init__(self, parent=None):
        super(MainWindow, self).__init__(parent)
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)
        self.setModal(True)
        self.ui.btnClose.clicked.connect(self.closeScanWindow)
        self.scanPath = ":/Users/Marwan/Desktop/ClamGuard"  # Init scan path
        self.LogPath = ""  # Init log path
        # self.ui.txtScan.append("Delete log file...")
        # self.clamscan = self.InitClamScan()  # Init path for clamscan
        # self.command = self.InitCommand()
        self.proc = QProcess(self)
        self.proc.finished.connect(self.OnScanProcFinished)
        # self.ui.btnCancelScan.clicked.connect(self.KillScan)
        self.ui.txtScan.setEnabled(False)
        self.isCancel = False
        # self.ui.btnClose.setIcon(QIcon(":/clamguard/images/close32.png"))
        # self.ui.btnCancelScan.setIcon(QIcon(":/clamguard/images/exit32.png"))
    def connect_to_dB(self):
        return create_server_connection("localhost", "root", "", "security_project")

    # calculating SHA-256 of file
    def hash_file(self, filePath):
        f = open(filePath, "rb")
        bytes = f.read()
        return hashlib.md5(bytes).hexdigest()

# iterate over files and files inside folders in the flash drive
    def detectUsbDrive (self, directory,connection):
        for path, subdirs, files in os.walk(directory):
            for name in files:
                f = os.path.join(path, name)
                # checking if it is a file
                if os.path.isfile(f):
                    self.ui.txtScan.append(f)
                    # t1 = time.time()
                    result = read_query(connection, "SELECT hash_id FROM virus_hashes WHERE hash = '{}'".format(self.hash_file(f)))
                    # t2 = time.time() - t1
                    # print(t2)
                    if result:
                        self.ui.txtScan.append("Malicous File Found.")
                        # deleting malicious file
                        os.remove(f)
                        self.ui.txtScan.append("Removing malicious file...")
                        time.sleep(1)
                        self.ui.txtScan.append("Malicous file removed.")
                        return
        self.ui.txtScan.append("USB drive is safe.")
    
    # if __name__ == "__main__":
    def program(self):
        # self.ui.txtScan.append("Delete log file...")
        connection = self.connect_to_dB()
        pythoncom.CoInitialize()
        c = wmi.WMI()
        list = [] 
        while True:   
            # checking inserted flash drives
            for disk in c.Win32_LogicalDisk():
                if disk.Description == 'Removable Disk' and not (list.count(disk.DeviceID)) :
                    # print(disk)
                    list.append(disk.DeviceID)
                    self.ui.txtScan.append("Detecting new driver called {} ({}\\)".format(disk.VolumeName, disk.DeviceID))
                    self.detectUsbDrive('{}\\'.format(disk.DeviceID), connection)

            # checking if the flash drives got ejected
            for i in range (len(list)) :
                found = 0 
                for disk in c.Win32_LogicalDisk():
                    if disk.Description == 'Removable Disk' and list[i] == disk.DeviceID :
                        found = 1 
                        break
                if (not found):
                    self.ui.txtScan.append("Driver {} ({}\\) got ejected".format(disk.VolumeName, disk.DeviceID))
                    list.remove(list[i])

    def OnScanProcFinished(self):
        try:
            if self.isCancel:
                self.ui.txtScan.append("Delete log file...")
                os.remove(self.LogPath)
                self.isCancel = False
        except Exception as e:
            self.ui.txtScan.append("ERROR: " + str(e))

    @QtCore.pyqtSlot()
    def on_readyReadStandardOutput(self):
        text = self.proc.readAllStandardOutput().data().decode()
        self.ui.txtScan.append(text.strip())

    def closeScanWindow(self):
        # check if proc is running
        try:
            if self.proc.state() == QProcess.ProcessState(2): # If proc RUNNING
                msg = QMessageBox()
                msg.setIcon(QMessageBox.Critical)
                msg.setText("Error")
                msg.setInformativeText('Please terminate scan before closing!')
                msg.setWindowTitle("Error")
                msg.exec_()
                return
            else:
                # proc is not running, close window
                self.close()
        except Exception as e:
            self.ui.txtScan.append("ERROR: " + str(e))
            self.close()

# def main():
#     app = QApplication(sys.argv)
#     app.setAttribute(Qt.AA_DontShowIconsInMenus, False)
#     w = MainWindow()
#     #   Disable maximize window button
#     w.setWindowFlags(Qt.WindowCloseButtonHint | Qt.WindowMinimizeButtonHint)
#     w.show()
#     sys.exit(app.exec_())

if __name__ == '__main__':
    # t1 = threading.Thread(target=main)
    # t1.start()
    app = QApplication(sys.argv)
    app.setAttribute(Qt.AA_DontShowIconsInMenus, False)
    w = MainWindow()
    #   Disable maximize window button
    w.setWindowFlags(Qt.WindowCloseButtonHint | Qt.WindowMinimizeButtonHint)
    w.show()
    t2 = threading.Thread(target=w.program, name="p")
    t2.daemon = True
    t2.start()
    sys.exit(app.exec_())
    # t1.join()
    # t2.join()
