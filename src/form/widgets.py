from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QDateTimeEdit, QLabel, QPushButton, QScrollArea, QCheckBox, QSpinBox
)
from PyQt5.QtCore import QDateTime
import sys
import datetime


class TimeFilterWidget(QWidget):
    def __init__(self, tittle, start_time, end_time):
        super().__init__()
        self.start_time = start_time
        self.end_time = end_time
        self.tittle = tittle
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel(self.tittle))

        # Создаем горизонтальное размещение для полей времени
        filter_layout = QHBoxLayout()

        # Виджет для выбора времени "От"
        filter_layout.addWidget(QLabel("От:"))
        self.start_time_w = QDateTimeEdit(self.start_time)
        self.start_time_w.setDisplayFormat("dd-MM-yyyy hh:mm:ss")
        filter_layout.addWidget(self.start_time_w)

        # Виджет для выбора времени "До"
        filter_layout.addWidget(QLabel("До:"))
        self.end_time_w = QDateTimeEdit(self.end_time)
        self.end_time_w.setDisplayFormat("dd-MM-yyyy hh:mm:ss")
        filter_layout.addWidget(self.end_time_w)
        layout.addLayout(filter_layout)


class CheckBoxFilterWidget(QWidget):
    def __init__(self, tittle, data_array):
        super().__init__()
        self.data_array = data_array
        self.tittle = tittle

        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()
        layout.addWidget(QLabel(self.tittle))

        # Создаем контейнер для чекбоксов с прокруткой
        scroll_area = QScrollArea(self)
        scroll_area.setWidgetResizable(True)

        # Контейнер для прокручиваемых виджетов
        scroll_content = QWidget(scroll_area)
        scroll_layout = QVBoxLayout(scroll_content)

        self.checkboxes = []
        for data in self.data_array:
            checkbox = QCheckBox(str(data))
            self.checkboxes.append(checkbox)
            scroll_layout.addWidget(checkbox)

        # Заключаем контейнер с чекбоксами в scroll_area
        scroll_area.setWidget(scroll_content)

        layout.addWidget(scroll_area)  # Добавляем прокручиваемую область в layout
        self.setLayout(layout)
        self.setFixedHeight(250)


class RangeFilterWidget(QWidget):
    def __init__(self, tittle, min_val, max_val):
        super().__init__()
        self.min_val = min_val
        self.max_val = max_val
        self.tittle = tittle
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel(self.tittle))

        # Создаем горизонтальное размещение для полей времени
        filter_layout = QHBoxLayout()

        # Виджет для выбора "От"
        filter_layout.addWidget(QLabel("От:"))
        self.min_spinbox = QSpinBox()
        self.min_spinbox.setRange(self.min_val, self.max_val)
        self.min_spinbox.setValue(self.min_val)
        filter_layout.addWidget(self.min_spinbox)

        # Виджет для выбора "До"
        filter_layout.addWidget(QLabel("До:"))
        self.max_spinbox = QSpinBox()
        self.max_spinbox.setRange(self.min_val, self.max_val)
        self.max_spinbox.setValue(self.max_val)
        filter_layout.addWidget(self.max_spinbox)
        layout.addLayout(filter_layout)

