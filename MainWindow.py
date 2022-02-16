# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'MainWindow.ui'
#
# Created by: PyQt5 UI code generator 5.15.1
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(757, 423)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(MainWindow.sizePolicy().hasHeightForWidth())
        MainWindow.setSizePolicy(sizePolicy)
        MainWindow.setMinimumSize(QtCore.QSize(757, 423))
        MainWindow.setMaximumSize(QtCore.QSize(757, 423))
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap(":/clamguard/Gerald-G-Clam-Security-Guard-ico32x32.png"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        MainWindow.setWindowIcon(icon)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.txtScan = QtWidgets.QTextEdit(self.centralwidget)
        self.txtScan.setGeometry(QtCore.QRect(10, 30, 741, 341))
        self.txtScan.setObjectName("txtScan")
        self.lblOutput = QtWidgets.QLabel(self.centralwidget)
        self.lblOutput.setGeometry(QtCore.QRect(10, 10, 54, 17))
        self.lblOutput.setObjectName("lblOutput")
        # self.btnCancelScan = QtWidgets.QPushButton(self.centralwidget)
        # self.btnCancelScan.setGeometry(QtCore.QRect(280, 380, 121, 29))
        # self.btnCancelScan.setObjectName("btnCancelScan")
        self.btnClose = QtWidgets.QPushButton(self.centralwidget)
        self.btnClose.setGeometry(QtCore.QRect(348, 380, 87, 29))
        self.btnClose.setObjectName("btnClose")
        # MainWindow.setCentralWidget(self.centralwidget)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "Scan for viruses"))
        self.lblOutput.setText(_translate("MainWindow", "Output"))
        # self.btnCancelScan.setText(_translate("MainWindow", "Cancel Scan"))
        self.btnClose.setText(_translate("MainWindow", "Close"))


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_ScanWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())