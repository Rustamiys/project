import sys
import os
import pandas as pd
import time

from PyQt5.QtCore import Qt, QTimer, QTime, QThread, pyqtSignal, QProcess
from PyQt5.QtGui import QPixmap, QMovie
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit, QTableWidget, QTableWidgetItem,
    QPushButton, QFileDialog, QSizePolicy, QDialog, QMessageBox, QScrollArea, QGridLayout, QInputDialog, QHeaderView
)
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
import matplotlib.pyplot as plt

from .widgets import TimeFilterWidget, CheckBoxFilterWidget, RangeFilterWidget
from stats.statistic import (filter_names, filter_dataframe, get_pie_type_size, get_dict_by_count_time,
    get_pie_type_count, get_pie_type_size_crypted, get_pie_type_count_crypted, get_dict_by_size,
    get_dict_by_size_time, get_pie_subtype_count, get_pie_subtype_size, get_pie_proto_size, get_pie_proto_count,
    network_utilization_rate, network_traffic_topology, port_activity, management_frames, get_speed_by_time, get_anomaly)
from datetime import datetime

from .utils import FileLoaderThread, LoadingDialog


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Анализатор данных")
        self.setGeometry(100, 100, 1900, 1000)
        self.setFixedSize(1900, 1000)

        self.project_dir = os.getcwd()

        self.add_main()

    def add_main(self):
        self.clear_screen()

        self.image_label = QLabel()
        self.image_label.setAlignment(Qt.AlignCenter)
        self.image_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.main_layout.addWidget(self.image_label)
        self.load_image()

        # Кнопки
        self.button_layout = QHBoxLayout()
        self.main_layout.addLayout(self.button_layout)

        self.analyze_button = QPushButton("Анализ")
        self.analyze_button.clicked.connect(self.analyz_traffic)
        self.button_layout.addWidget(self.analyze_button)

        self.stats_button = QPushButton("Статистика")
        self.stats_button.clicked.connect(self.show_stats)
        self.button_layout.addWidget(self.stats_button)

        self.current_graph_widget = None

    def add_filter_buttons(self):
        self.button_layout = QHBoxLayout()
        self.main_layout.addLayout(self.button_layout)
        self.main_button = QPushButton("Вернуться на начальное окно")
        self.main_button.clicked.connect(self.add_main)
        self.button_layout.addWidget(self.main_button)

        self.create_diagram = QPushButton("Построить диаграму")
        self.create_diagram.clicked.connect(self.plot_diagram)
        self.button_layout.addWidget(self.create_diagram)

        self.create_diagram = QPushButton("Построить гистограму")
        self.create_diagram.clicked.connect(self.plot_histogram)
        self.button_layout.addWidget(self.create_diagram)

        self.clean_filter = QPushButton("Очистить фильтры")
        self.clean_filter.clicked.connect(self.paint_filters)
        self.button_layout.addWidget(self.clean_filter)

    def add_filter_buttons_plot(self):
        self.button_layout = QHBoxLayout()
        self.main_layout.addLayout(self.button_layout)
        self.filter_button = QPushButton("Вернуться к фильтрам")
        self.filter_button.clicked.connect(self.paint_filters)
        self.button_layout.addWidget(self.filter_button)

        self.create_diagram = QPushButton("Поиск аномалий")
        self.create_diagram.clicked.connect(self.create_table)
        self.button_layout.addWidget(self.create_diagram)

    def create_table(self):
        self.clear_screen()

        all_anomaly = get_anomaly(self.filtered_df)

        self.button_layout = QHBoxLayout()
        self.main_layout.addLayout(self.button_layout)
        self.filter_button = QPushButton("Вернуться к фильтрам")
        self.filter_button.clicked.connect(self.paint_filters)
        self.button_layout.addWidget(self.filter_button)

        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setRowCount(len(all_anomaly))
        self.table.setHorizontalHeaderLabels(["Тип аномалии", "Описание аномалий", "Описание последствий", "Уровень"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setWordWrap(True)
        self.table.resizeRowsToContents() 

        layout = QVBoxLayout()
        layout.addWidget(self.table)

        for row, anomaly in enumerate(all_anomaly):
            for col, value in enumerate(anomaly):
                item = QTableWidgetItem(str(value))
                self.table.setItem(row, col, item)
        self.table.resizeRowsToContents()
        self.main_layout.addLayout(layout)


    def load_image(self):
        image_path = os.path.join(self.project_dir, "static", "img.png")
        if os.path.exists(image_path):
            pixmap = QPixmap(image_path)
            self.image_label.setPixmap(pixmap.scaled(
                self.image_label.size(), Qt.KeepAspectRatio, Qt.SmoothTransformation))
        else:
            self.image_label.setText("Изображение не найдено.")

    def clear_screen(self):
        if hasattr(self, 'button_layout'):
            while self.button_layout.count():
                child = self.button_layout.takeAt(0)
                if child.widget():
                    child.widget().deleteLater()
        if hasattr(self, 'main_layout'):
            while self.main_layout.count():
                child = self.main_layout.takeAt(0)
                if child.widget():
                    child.widget().deleteLater()
        self.main_widget = QWidget()
        self.setCentralWidget(self.main_widget)
        self.main_layout = QVBoxLayout(self.main_widget)


    def show_stats(self):
        self.clear_screen()

        tmp_dir = os.path.join(self.project_dir, "tmp")
        if not os.path.exists(tmp_dir):
            os.makedirs(tmp_dir)

        filename, _ = QFileDialog.getOpenFileName(
            self, "Выберите файл .pcap или .cap", tmp_dir, "PCAP Files (*.pcap *.cap)"
        )

        if filename:
            self.dialog = LoadingDialog(self)
            self.dialog.show()

            self.thread = FileLoaderThread(filename)
            self.thread.finished.connect(self.on_file_loaded)
            self.thread.start()

    def on_file_loaded(self, df):
        self.dialog.close()
        
        if df is not None:
            self.df = df
            self.paint_filters()
        else:
            QMessageBox.critical(self, "Ошибка", "Не удалось загрузить файл.")

    def paint_filters(self):
        self.filters(self.df)

    def filters(self, df):
        self.clear_screen()
        self.df = df
        #  main
        central_widget = QWidget()
        self.main_layout = QVBoxLayout(central_widget)
        # scroll 
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setWidget(central_widget)
        self.setCentralWidget(scroll_area)
        # buttons
        self.add_filter_buttons()

        if df.empty:
            QMessageBox.critical(self, "Ошибка", "Файл не удалось обработать.")
        self.time_filter_widget = TimeFilterWidget(filter_names["time"], datetime.fromtimestamp(df['time'].min()), 
                                                   datetime.fromtimestamp(df['time'].max()))
        self.size_widget = RangeFilterWidget(filter_names["len"], df["len"].min(), df["len"].max())
        self.type_widget = CheckBoxFilterWidget(filter_names["type"], df["type"].unique())
        
        grid_layout = QGridLayout()

        if "subtype" in df.columns:
            self.subtype_widget = CheckBoxFilterWidget(filter_names["subtype"], df["subtype"].unique())
            self.addr1_widget = CheckBoxFilterWidget(filter_names["addr1"], df["addr1"].unique())
            self.addr2_widget = CheckBoxFilterWidget(filter_names["addr2"], df["addr2"].unique())
            self.addr3_widget = CheckBoxFilterWidget(filter_names["addr3"], df["addr3"].unique())

            grid_layout.addWidget(self.subtype_widget, 0, 0)
            grid_layout.addWidget(self.type_widget, 0, 1)
            grid_layout.addWidget(self.addr1_widget, 1, 0)
            grid_layout.addWidget(self.addr2_widget, 1, 1)
            grid_layout.addWidget(self.addr3_widget, 2, 0)
            grid_layout.addWidget(self.time_filter_widget, 3, 0)
            grid_layout.addWidget(self.size_widget, 3, 1)
        else:
            self.src_widget = CheckBoxFilterWidget(filter_names["src"], df["src"].unique())
            self.dst_widget = CheckBoxFilterWidget(filter_names["dst"], df["dst"].unique())
            self.proto_widget = CheckBoxFilterWidget(filter_names["proto"], df["proto"].unique())
            self.ip_src_widget = CheckBoxFilterWidget(filter_names["ip_src"], df["ip_src"].unique())
            self.ip_dst_widget = CheckBoxFilterWidget(filter_names["ip_dst"], df["ip_dst"].unique())
            self.ip_src_port_widget = CheckBoxFilterWidget(filter_names["ip_src_port"], df["ip_src_port"].unique())
            self.ip_dst_port_widget = CheckBoxFilterWidget(filter_names["ip_dst_port"], df["ip_dst_port"].unique())

            grid_layout.addWidget(self.type_widget, 0, 0)
            grid_layout.addWidget(self.proto_widget, 0, 1)
            grid_layout.addWidget(self.src_widget, 1, 0)
            grid_layout.addWidget(self.dst_widget, 1, 1)
            grid_layout.addWidget(self.ip_src_widget, 2, 0)
            grid_layout.addWidget(self.ip_dst_widget, 2, 1)
            grid_layout.addWidget(self.ip_src_port_widget, 3, 0)
            grid_layout.addWidget(self.ip_dst_port_widget, 3, 1)
            grid_layout.addWidget(self.time_filter_widget, 4, 0)
            grid_layout.addWidget(self.size_widget, 4, 1)
    
        self.main_layout.addLayout(grid_layout)
    
    def data_filter_proccessing(self):
        df = self.df
        filter_dict = {}
        filter_dict_interval = {
            "len": [
                int(self.size_widget.min_spinbox.value()),
                int(self.size_widget.max_spinbox.value())
            ],
            "time": [
                self.time_filter_widget.start_time_w.dateTime().toSecsSinceEpoch(),
                self.time_filter_widget.end_time_w.dateTime().toSecsSinceEpoch() + 1
            ]
        }

        def collect_checked_text(widget, key):
            selected = [cb.text() for cb in widget.checkboxes if cb.isChecked()]
            if selected:
                filter_dict[key] = selected

        if "subtype" in df.columns:
            collect_checked_text(self.subtype_widget, "subtype")
            collect_checked_text(self.type_widget, "type")
            collect_checked_text(self.addr1_widget, "addr1")
            collect_checked_text(self.addr2_widget, "addr2")
            collect_checked_text(self.addr3_widget, "addr3")
        else:
            collect_checked_text(self.type_widget, "type")
            collect_checked_text(self.proto_widget, "proto")
            collect_checked_text(self.src_widget, "src")
            collect_checked_text(self.dst_widget, "dst")
            collect_checked_text(self.ip_dst_widget, "ip_dst")
            collect_checked_text(self.ip_src_widget, "ip_src")
            collect_checked_text(self.ip_src_port_widget, "ip_src_port")
            collect_checked_text(self.ip_dst_port_widget, "ip_dst_port")
        
        self.filtered_df = filter_dataframe(df, filter_dict, filter_dict_interval)

    def plot_diagram(self):
        self.clear_screen()
        self.data_filter_proccessing()
        self.add_filter_buttons_plot()
        grid_layout = QGridLayout()
        graph_widget = QWidget()
        df = self.filtered_df
        if "subtype" in df.columns:
            pie_data_functions = [
                ("Диаграмма по type(по размеру)", get_pie_type_size_crypted),
                ("Диаграмма по type(по кол-ву)", get_pie_type_count_crypted),
                ("Диаграмма по subtype(по размеру)", get_pie_subtype_size),
                ("Диаграмма по subtype(по кол-ву)", get_pie_subtype_count),
            ]
            i = 0
            for title, func in pie_data_functions:
                pie_data, measure = func(df)
                fig = plt.Figure()
                ax = fig.add_subplot(111)
                values = pie_data.values()
                labels = pie_data.keys()
                ax.set_aspect('equal')
                ax.pie(values, autopct='%1.1f%%',center=(-10, 0),)
                ax.legend(
                    [f'{label}: {size} {measure}' for label, size in zip(labels, values)],
                    loc="center left",
                    fontsize=8,
                    bbox_to_anchor=(-1, 0, 0.5, 1)
                )
                ax.set_title(title)
                fig.subplots_adjust(left=0.4, right=0.95)
                grid_layout.addWidget(FigureCanvas(fig), i//2, i%2)
                i += 1
        else:
            pie_data_functions = [
                ("Диаграмма по type(по размеру)", get_pie_type_size),
                ("Диаграмма по type(по кол-ву)", get_pie_type_count),
                ("Диаграмма по proto(по размеру)", get_pie_proto_size),
                ("Диаграмма по proto(по кол-ву)", get_pie_proto_count),
            ]
            i = 0
            for title, func in pie_data_functions:
                pie_data, measure = func(df)
                fig = plt.Figure()
                ax = fig.add_subplot(111)
                values = pie_data.values()
                labels = pie_data.keys()
                ax.set_aspect('equal')
                ax.pie(values, autopct='%1.1f%%',center=(-10, 0),)
                ax.legend(
                    [f'{label}: {size} {measure}' for label, size in zip(labels, values)],
                    loc="center left",
                    fontsize=8,
                    bbox_to_anchor=(-1, 0, 0.5, 1)
                )
                ax.set_title(title)
                fig.subplots_adjust(left=0.4, right=0.95)
                grid_layout.addWidget(FigureCanvas(fig), i//2, i%2)
                i += 1

        self.main_layout.addLayout(grid_layout)
        self.current_graph_widget = graph_widget

    def plot_histogram(self):
        self.clear_screen()
        self.data_filter_proccessing()
        self.add_filter_buttons_plot()
        grid_layout = QGridLayout()
        graph_widget = QWidget()
        df = self.filtered_df
        plot_functions = [
            ("Гистограмма по размеру", get_dict_by_size_time),
            ("Гистограмма по размеру", get_dict_by_size),
            ("Гистограмма по кол-ву", get_dict_by_count_time),
        ]
        for i, (title, func) in enumerate(plot_functions):
            plot_data, ylabel = func(df)
            fig = plt.Figure()
            ax = fig.add_subplot(111)
            ax.bar(plot_data['time_bin'], plot_data['value'], width=1.0, align='edge')
            ax.legend(
                [f'{label}: {size}' for label, size in zip(plot_data['time_bin'], plot_data['value'])],
                loc="center left",
                fontsize=8,
                bbox_to_anchor=(-1, 0, 0.5, 1)
            )
            ax.set_xlabel('Временные интервалы')
            ax.set_ylabel(ylabel)
            ax.set_title(title)  # Используем переданный заголовок
            ax.tick_params(axis='x', labelrotation=45)
            ax.grid(axis='y', linestyle='--', alpha=0.7)
            grid_layout.addWidget(FigureCanvas(fig), i//2, i%2)

        # Скорость
        size_group = get_speed_by_time(df)
        fig = plt.Figure()
        ax = fig.add_subplot(111)
        # Цвета для линий (можно настроить)
        colors = plt.cm.tab10.colors
        bin_size=100
        # Построение графиков для каждой пары IP
        for i, (key, data) in enumerate(size_group.items()):
            time_bins = sorted(data.keys())
            x = time_bins  # Время в секундах
            y = [data[t] / (1024 * 1024) / bin_size for t in time_bins]  # МБ/с
            
            ax.plot(
                x, y,
                'o-',  # Точки с линиями
                markersize=4,
                linewidth=2,
                color=colors[i % len(colors)],
                label=f"{key}"
            )

        ax.set_xlabel('Время (секунды)')
        ax.set_ylabel('Скорость передачи (МБ/с)')
        ax.set_title(f'Линейный график мгновенной скорости для каждого подключенного MAC c {pd.to_datetime(df['time'].min(), unit='s').strftime('%H:%M:%S')} по {pd.to_datetime(df['time'].max(), unit='s').strftime('%H:%M:%S')}')
        ax.legend()
        ax.grid(True, linestyle='--', alpha=0.7)
        grid_layout.addWidget(FigureCanvas(fig), 1, 1)

        self.main_layout.addLayout(grid_layout)
        self.current_graph_widget = graph_widget

    def analyz_traffic(self):
        # Очищаем экран и создаем новую компоновку
        self.clear_screen()
        
        # Создаем область для вывода команд
        self.output_area = QTextEdit()
        self.output_area.setReadOnly(True)
        self.main_layout.addWidget(self.output_area)
        
        # Создаем кнопки
        self.button_layout = QHBoxLayout()
        self.main_layout.addLayout(self.button_layout)
        
        self.start_button = QPushButton("Начать анализ")
        self.start_button.setEnabled(False)
        self.start_button.clicked.connect(self.start_analysis)
        self.button_layout.addWidget(self.start_button)
        
        self.stop_button = QPushButton("Остановить")
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_analysis)
        self.button_layout.addWidget(self.stop_button)
        
        # Запускаем процесс мониторинга
        self.start_monitoring()
        
    def start_monitoring(self):
        """Запускает процесс мониторинга сети"""
        self.output_area.append("Запуск мониторинга сети...")
        
        # Запускаем команды для перевода интерфейса в режим мониторинга
        commands = [
            "sudo airmon-ng check kill",
            "sudo airmon-ng start wlan1",
            "sudo airodump-ng wlan1mon"
        ]
        
        # Создаем процесс для выполнения команд
        self.monitor_process = QProcess()
        self.monitor_process.readyReadStandardOutput.connect(self.update_output)
        self.monitor_process.readyReadStandardError.connect(self.update_output)
        
        # Запускаем команды последовательно
        full_command = " && ".join(commands)
        self.monitor_process.start("bash", ["-c", full_command])
        
        # Включаем кнопку "Начать анализ" после запуска мониторинга
        self.start_button.setEnabled(True)
        
    def update_output(self):
        """Обновляет вывод в текстовом поле"""
        output = self.monitor_process.readAllStandardOutput().data().decode()
        error = self.monitor_process.readAllStandardError().data().decode()
        
        if output:
            self.output_area.append(output)
        if error:
            self.output_area.append(f"Ошибка: {error}")
        
        # Здесь можно добавить парсинг вывода для автоматического определения устройств
        
    def start_analysis(self):
        """Начинает  конкретного устройства"""
        # Получаем MAC и канал из интерфейса (можно добавить виджеты для ввода)
        bssid, ok = QInputDialog.getText(self, "Введите данные", "MAC адрес устройства:")
        if not ok or not bssid:
            return
            
        channel, ok = QInputDialog.getText(self, "Введите данные", "Канал устройства:")
        if not ok or not channel:
            return
        
        self.output_area.append(f"\nНачинаем  устройства {bssid} на канале {channel}...")
        
        # Останавливаем мониторинг
        self.monitor_process.terminate()
        
        # Запускаем  конкретного устройства
        self.analysis_process = QProcess()
        self.analysis_process.readyReadStandardOutput.connect(self.update_output)
        self.analysis_process.readyReadStandardError.connect(self.update_output)
        
        command = f"sudo airodump-ng --bssid {bssid} -c {channel} --write dump wlan1mon"
        self.analysis_process.start("bash", ["-c", command])
        
        # Включаем кнопку "Остановить"
        self.stop_button.setEnabled(True)
        self.start_button.setEnabled(False)
        
    def stop_analysis(self):
        """Останавливает анализ и выполняет декодирование"""
        if hasattr(self, 'analysis_process') and self.analysis_process:
            self.analysis_process.terminate()
            
        # Запрашиваем данные для декодирования
        essid, ok = QInputDialog.getText(self, "Введите данные", "ESSID сети:")
        if not ok or not essid:
            return
            
        password, ok = QInputDialog.getText(self, "Введите данные", "Пароль сети:")
        if not ok or not password:
            return
            
        bssid, ok = QInputDialog.getText(self, "Введите данные", "MAC адрес устройства:")
        if not ok or not bssid:
            return
        
        # Выполняем декодирование
        self.output_area.append("\nЗапуск декодирования...")
        command = f'sudo airdecap-ng -e {essid} -p {password} -b {bssid} dump-01.cap'
        
        self.decap_process = QProcess()
        self.decap_process.readyReadStandardOutput.connect(self.update_output)
        self.decap_process.readyReadStandardError.connect(self.update_output)
        self.decap_process.start("bash", ["-c", command])
        
        self.stop_button.setEnabled(False)