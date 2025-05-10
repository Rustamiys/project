import sys
import os
import pandas as pd
import time

from PyQt5.QtCore import Qt, QTimer, QTime, QThread, pyqtSignal
from PyQt5.QtGui import QPixmap, QMovie
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QFileDialog, QSizePolicy, QDialog, QMessageBox, QScrollArea, QGridLayout
)
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
import matplotlib.pyplot as plt

from stats.reader import read_pcap

from .widgets import TimeFilterWidget, CheckBoxFilterWidget, RangeFilterWidget
from stats.statistic import (filter_names, filter_dataframe, get_pie_type_size, 
                    get_pie_type_count, get_pie_type_size_crypted, get_pie_type_count_crypted,
                    get_pie_subtype_count, get_pie_subtype_size, get_pie_proto_size, get_pie_proto_count)
from datetime import datetime

# # Заглушка: симулируем чтение файла
# def read_pcap(filename):
#     # time.sleep(3)  # эмуляция долгой загрузки
#     data = {
#         'type': [34525, 2048, 2048, 34525, 2048],
#         'len': [86, 354, 590, 110, 471],
#         'time': [
#             1745226379.370546,
#             1745226379.403280,
#             1745226379.409454,
#             1745226379.427990,
#             1745226456.680689
#         ],
#         'src': [
#             'e8:5a:8b:0b:8d:7c',
#             'e8:5a:8b:0b:8d:7c',
#             'b0:a7:b9:b2:ec:9e',
#             'e8:5a:8b:0b:8d:7c',
#             'b0:a7:b9:b2:ec:9e'
#         ],
#         'dst': [
#             '33:33:ff:c3:04:43',
#             'ff:ff:ff:ff:ff:ff',
#             'e8:5a:8b:0b:8d:7c',
#             '33:33:00:00:00:16',
#             'e8:5a:8b:0b:8d:7c'
#         ],
#         'proto': [None, 17.0, 17.0, None, 6.0],
#         'ip_src': ['::', '0.0.0.0', '192.168.0.1', '::', '87.240.137.208'],
#         'ip_dst': ['ff02::1:ffc3:443', '255.255.255.255', '192.168.0.104', 'ff02::16', '192.168.0.104'],
#         'ip_src_port': [None, 68.0, 67.0, None, 443.0],
#         'ip_dst_port': [None, 67.0, 68.0, None, 47934.0]
#     }

#     df = pd.DataFrame(data)
#     return df

class FileLoaderThread(QThread):
    finished = pyqtSignal(object)

    def __init__(self, filename):
        super().__init__()
        self.filename = filename

    def run(self):
        try:
            df = read_pcap(self.filename)
            self.finished.emit(df)
        except Exception as e:
            print(f"Ошибка при чтении файла: {e}")
            self.finished.emit(None)


class LoadingDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Загрузка")
        self.setWindowModality(Qt.WindowModal)
        self.setFixedSize(220, 200)
        self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignCenter)

        self.movie_label = QLabel(self)
        self.movie_label.setFixedSize(80, 80)
        self.movie_label.setAlignment(Qt.AlignCenter)

        # Путь к GIF
        project_dir = os.getcwd()
        gif_path = os.path.join(project_dir, "static", "loading.gif")

        if os.path.exists(gif_path):
            self.movie = QMovie(gif_path)
            if self.movie.isValid():
                self.movie.setScaledSize(self.movie_label.size())
                self.movie_label.setMovie(self.movie)
                self.movie.start()
            else:
                self.movie_label.setText("Ошибка: GIF поврежден")
        else:
            self.movie_label.setText("GIF не найден")

        # Таймер
        self.time = QTime(0, 0, 0)
        self.time_label = QLabel("Время: 00:00", self)
        self.time_label.setAlignment(Qt.AlignCenter)
        self.time_label.setStyleSheet("font-size: 14px; color: white;")

        layout.addWidget(self.movie_label)
        layout.addSpacing(10)
        layout.addWidget(self.time_label)

        self.setStyleSheet("background-color: #1e1e1e;")

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_time)
        self.timer.start(1000)

    def update_time(self):
        self.time = self.time.addSecs(1)
        self.time_label.setText(f"Время: {self.time.toString('mm:ss')}")

    def stop_loading(self):
        if self.timer.isActive():
            self.timer.stop()
        if hasattr(self, 'movie') and self.movie.state() == QMovie.Running:
            self.movie.stop()

    def closeEvent(self, event):
        self.stop_loading()
        event.accept()
