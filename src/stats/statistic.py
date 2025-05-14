import pandas as pd
import numpy as np

filter_names = {
    "subtype":"Подтип фрейма",
    "type":"тип пакета",
    "addr1":"Получатель (Destination MAC)",
    "addr2":"Отправитель (Source MAC)",
    "addr3":"BSSID (MAC точки доступа)",
    "time":"Время перехвата",
    "len":"длина пакета",
    "src":"MAC-адрес отправителя",
    "dst":"MAC-адрес получателя",
    "proto":"Протокол",
    "ip_src":"IP-адрес отправителя",
    "ip_dst":"IP-адрес получателя",
    "ip_src_port":"Исходный порт",
    "ip_dst_port":"Порт назначения"
}


protocol_names = {
    1: "ICMP (Internet Control\n Message Protocol)",
    6: "TCP (Transmission\n Control Protocol)",
    17: "UDP (User Datagram\n Protocol)",
    2: "IGMP (Internet Group\n Management Protocol)",
    34525: "IPv6 (EtherType \n 0x86DD)",
    2048: "IPv4 (EtherType\n 0x0800)",
    2054: "ARP (Address Resolution\n Protocol)",
    33024: "802.1Q VLAN-tagged\n frame",
}

types_crypted = {
    0: "Management (Управляющие\n кадры)",
    1: "Control (Контрольные\n кадры)",
    2: "Data (Кадры данных)",
    3: "Extension (Зарезервирован\n в 802.11n/ac/ax)"
}

subtype_crypted = {
    0:{
        0:	f"{types_crypted[0]} - Association Request",
        1:	f"{types_crypted[0]} - Association Response",
        2:	f"{types_crypted[0]} - Reassociation Request",
        3:	f"{types_crypted[0]} - Reassociation Response",
        4:	f"{types_crypted[0]} - Probe Request",
        5:	f"{types_crypted[0]} - Probe Response",
        6:	f"{types_crypted[0]} - Timing Advertisement",
        7:	f"{types_crypted[0]} - Reserved",
        8:	f"{types_crypted[0]} - Beacon",
        9:	f"{types_crypted[0]} - ATIM",
        10:	f"{types_crypted[0]} - Disassociation",
        11:	f"{types_crypted[0]} - Authentication",
        12:	f"{types_crypted[0]} - Deauthentication",
        13:	f"{types_crypted[0]} - Action",
        14:	f"{types_crypted[0]} - Action No Ack",
        15:	f"{types_crypted[0]} - Reserved"
    },
    1:{
        0:	f"{types_crypted[1]} - Reserved",
        1:	f"{types_crypted[1]} - RTS (Request To Send)",
        2:	f"{types_crypted[1]} - CTS (Clear To Send)",
        3:	f"{types_crypted[1]} - ACK (Acknowledgment)",
        4:	f"{types_crypted[1]} - CF-End",
        5:	f"{types_crypted[1]} - CF-End + CF-ACK",
        6:	f"{types_crypted[1]} - Control Wrapper",
        7:	f"{types_crypted[1]} - Block Ack Request (BAR)",
        8:	f"{types_crypted[1]} - Block Ack (BA)",
        9:	f"{types_crypted[1]} - PS-Poll",
        10:	f"{types_crypted[1]} - RTS (повторно зарезерв.)",
        11:	f"{types_crypted[1]} - (RTS тоже, или QoS+Ctrl)",
        12: f"{types_crypted[1]} - Reserve",
        13: f"{types_crypted[1]} - Reserve",
        14: f"{types_crypted[1]} - Reserved",
        15: f"{types_crypted[1]} - Reserved",
    },
    2:{
        0:	f"{types_crypted[2]} - Data",
        1:	f"{types_crypted[2]} - Data + CF-ACK",
        2:	f"{types_crypted[2]} - Data + CF-Poll",
        3:	f"{types_crypted[2]} - Data + CF-ACK +\n CF-Poll",
        4:	f"{types_crypted[2]} - Null Data (no data,\n just control)",
        5:	f"{types_crypted[2]} - CF-ACK (no data)",
        6:	f"{types_crypted[2]} - CF-Poll (no data)",
        7:	f"{types_crypted[2]} - CF-ACK + CF-Poll\n (no data)",
        8:	f"{types_crypted[2]} - QoS Data",
        9:	f"{types_crypted[2]} - QoS Data +\n CF-ACK",
        10:	f"{types_crypted[2]} - QoS Data +\n CF-Poll",
        11:	f"{types_crypted[2]} - QoS Data +\n CF-ACK + CF-Poll",
        12:	f"{types_crypted[2]} - QoS Null \n(QoS control only)",
        13: f"{types_crypted[2]} - Reserved",
        14: f"{types_crypted[2]} - Reserved",
        15:	f"{types_crypted[2]} - Reserved"
    },
    3:{
        0: f"{types_crypted[3]} - Reserved",
        1: f"{types_crypted[3]} - Reserved",
        2: f"{types_crypted[3]} - Reserved",
        3: f"{types_crypted[3]} - Reserved",
        4: f"{types_crypted[3]} - Reserved",
        5: f"{types_crypted[3]} - Reserved",
        6: f"{types_crypted[3]} - Reserved",
        7: f"{types_crypted[3]} - Reserved",
        8: f"{types_crypted[3]} - Reserved",
        9: f"{types_crypted[3]} - Reserved",
        10: f"{types_crypted[3]} - Reserved",
        11: f"{types_crypted[3]} - Reserved",
        12: f"{types_crypted[3]} - Reserved",
        13: f"{types_crypted[3]} - Reserved",
        14: f"{types_crypted[3]} - Reserved",
        15: f"{types_crypted[3]} - Reserved",
    }
}

def filter_by_filter_dict(df, filter_dict):
    for i in filter_dict.keys():
        df = df[df[i].isin(filter_dict[i])]
    return df

def filter_by_filter_dict_interval(df, filter_dict):
    for i in filter_dict.keys():
        df = df[(df[i] >= filter_dict[i][0]) & (df[i] <= filter_dict[i][1])]
    return df

def filter_dataframe(df, filter_dict, filter_dict_interval):
    df = filter_by_filter_dict(df, filter_dict)
    df = filter_by_filter_dict_interval(df, filter_dict_interval)
    return df

def get_pie_type_size(df):
    dt = (df.groupby('type')['len'].sum() / (1024  * 1024)).to_dict()
    dt = {k: round(v, 3) for k, v in dt.items()}

    return dt, "Mb"

def get_pie_type_count(df):
    dt = df["type"].value_counts().to_dict()
    return dt, ""

def get_pie_type_count_crypted(df):
    dt = df["type"].value_counts().to_dict()
    return dt, ""

def get_pie_type_size_crypted(df):
    dt = (df.groupby('type')['len'].sum() / (1024  * 1024)).to_dict()
    dt = {k: round(v, 3) for k, v in dt.items()}

    return dt, "Mb"

def get_pie_proto_count(df):
    dt = df["proto"].value_counts().to_dict()
    return dt, ""

def get_pie_proto_size(df):
    dt = (df.groupby('proto')['len'].sum() / (1024  * 1024)).to_dict()
    dt = {k: round(v, 3) for k, v in dt.items()}

    return dt, "Mb"

def get_dict_by_size_time(df):

    min_time = df['time'].min()
    max_time = df['time'].max()
    total_range = max_time - min_time
    bin_count = 20
    if pd.isna(total_range):
        total_range = 1
    interval = round(total_range / bin_count)
    if interval <= 0:
        interval = 1
    bins = np.arange(min_time, max_time + interval, interval)
    labels = pd.to_datetime(bins[:-1], unit='s').strftime('%H:%M:%S')

    df['time_bin'] = pd.cut(df['time'], bins=bins, labels=labels, include_lowest=True)
    df_grouped = df.groupby('time_bin')['len'].sum().reset_index(name='value')
    df_grouped['value'] = (df_grouped['value'] / (1024 * 1024)).round(3)
    return df_grouped, "Размер пакетов"

def get_dict_by_size(df):
    if df.empty:
        return {'time_bin': [], 'value': []}, "Размер пакетов"
    
    # Создаем bins для группировки по размеру
    max_len = df['len'].max()
    bins = np.arange(0, max_len + 100, 100)
    
    # Группируем данные по диапазонам размеров
    df['size_group'] = pd.cut(df['len'], bins=bins, right=False)
    size_counts = df['size_group'].value_counts().sort_index()
    
    # Подготавливаем данные для графика
    plot_data = {
        'time_bin': [str(interval) for interval in size_counts.index],
        'value': size_counts.values
    }
    
    return plot_data, "Количество пакетов по размеру"


def get_dict_by_count_time(df):

    min_time = df['time'].min()
    max_time = df['time'].max()
    total_range = max_time - min_time
    bin_count = 20
    if pd.isna(total_range):
        total_range = 1
    interval = round(total_range / bin_count)
    if interval <= 0:
        interval = 1
    bins = np.arange(min_time, max_time + interval, interval)
    labels = pd.to_datetime(bins[:-1], unit='s').strftime('%H:%M:%S')

    df['time_bin'] = pd.cut(df['time'], bins=bins, labels=labels, include_lowest=True)
    df_grouped = df.groupby('time_bin').size().reset_index(name='value')

    return df_grouped, "Количество пакетов"

def get_pie_subtype_count(df):
    dt = df["subtype"].value_counts().to_dict()
    return dt, ""

def get_pie_subtype_size(df):
    dt = (df.groupby('subtype')['len'].sum() / (1024  * 1024)).to_dict()
    dt = {k: round(v, 3) for k, v in dt.items()}
    return dt, "Mb"

def detect_network_utilization_anomalies(df, bandwidth_bps=100_000_000, interval=1.0):
    """
    Анализирует загрузку сети и выявляет аномалии по временам превышения заданных порогов.

    Параметры:
        df (pd.DataFrame): DataFrame с колонками ['time', 'len']
        bandwidth_bps (int): Пропускная способность канала в битах/сек (по умолчанию 100 Мбит/с)
        interval (float): Интервал времени группировки в секундах (по умолчанию 1 секунда)

    Возвращает:
        pd.DataFrame: Таблица с колонками ['time_sec', 'bytes', 'utilization_pct', 'status']
        где 'status' — это одна из меток: 'normal', 'warning', 'critical'
    """

    df = df.copy()
    df['time_sec'] = (df['time'] // interval).astype(int) * interval

    # Суммируем байты по интервалам
    traffic = df.groupby('time_sec')['len'].sum().reset_index()
    traffic['bits'] = traffic['len'] * 8
    traffic['utilization_pct'] = (traffic['bits'] / (bandwidth_bps * interval)) * 100

    # Определяем статус
    def status(util):
        if util > 80:
            return 'critical'
        elif util > 70:
            return 'warning'
        else:
            return 'normal'

    traffic['status'] = traffic['utilization_pct'].apply(status)

    return traffic

def network_utilization_rate(df, bandwidth_bps=100_000_000):
    diff = (df['time'].max() - df['time'].min())
    if diff != 0:
        return 100 * df['len'].sum() * 8/(bandwidth_bps * diff)
    return -1

def distribution_of_network_protocols_by_type(df):
    counts = df["type"].value_counts()
    percentages = (counts / counts.sum() * 100).round(2).to_dict()
    return percentages

def distribution_of_network_protocols_by_proto(df):
    counts = df["proto"].value_counts()
    percentages = (counts / counts.sum() * 100).round(2).to_dict()
    return percentages

def network_traffic_topology(df):
    mask = ~(
        df["ip_src"].str.startswith("192.168.") |
        df["ip_src"].str.startswith("0.0.0.0") |
        df["ip_src"].str.startswith("f") |
        df["ip_src"].str.startswith(":")
    )
    df = df[mask]
    counts = df["ip_src"].value_counts()
    percentages = (counts / counts.sum() * 100).round(2).to_dict()
    return percentages
    

def port_activity(df):
    mask = ~(
        df["ip_src"].str.startswith("192.168.") |
        df["ip_src"].str.startswith("0.0.0.0") |
        df["ip_src"].str.startswith("f") |
        df["ip_src"].str.startswith(":")
    )

    df = df[~df["ip_src_port"].isin(["80", "53", "443", "22", "137", "138", "139", "445", "123"])]
    df = df[mask]
    combo = df["ip_src"].astype(str) + ":" + df["ip_src_port"].astype(str)
    result = combo.value_counts().to_dict()
    return result

def management_frames(df):
    df = df[df["type"] == types_crypted[0]]
    counts = df["subtype"].value_counts()
    percentages = (counts / counts.sum() * 100).round(2).to_dict()
    return percentages

def control_frames(df):
    df = df[df["type"] == types_crypted[1]]
    counts = df["subtype"].value_counts()
    percentages = (counts / counts.sum() * 100).round(2).to_dict()
    return percentages

def get_speed_by_time(df):
    bin_size=100
    start_time = df['time'].min()
    interval = (df['time'].max() - start_time) / bin_size 
    df['time_bin'] = ((df['time'] - start_time) // interval).astype(int)
    true_key = ["82:D0:B1:13:30:10", #iphone Farid
                "4C:79:6E:58:43:50", #nout Farid
                "E8:5A:8B:0B:8D:7C", #phone Rustam
                "B0:A7:B9:B2:EC:9E"]
    size_group = {}
    if "subtype" in df:
        key = "addr2"
    else:
        key = "src"
    for _, row in df.iterrows(): 
        src = row[key]
        time_bin = row['time_bin']
        # if not src in true_key:
        #     continue
        if src not in size_group:
            size_group[src] = {}
        
        if time_bin not in size_group[src]:
            size_group[src][time_bin] = 0
        
        size_group[src][time_bin] += row['len']
    return size_group


def get_anomaly(df):
    anomalies = []

    # Загрузка сети
    urate = network_utilization_rate(df)
    if urate>=0 and urate <=70:
        anomalies.append(["Загрузка сети (Network Utilization)", "", "", "Нормальные значения"])
    elif urate<=80 and urate >=70:
        anomalies.append(["Загрузка сети (Network Utilization)", "", "", "Предупреждающая зона"])
    elif urate>80:
        anomalies.append(["Загрузка сети (Network Utilization)", "Превышение порога в 80% свидетельствует о риске потерь данных и нестабильной работе сети.", "Возможны потери пакетов, перегрузка буферов", "Аномалия"])


    if "subtype" in df.columns:
        # Management–фреймы (Тип 0)
        manage = management_frames(df)
        if subtype_crypted[0][12] in manage:
            if manage[subtype_crypted[0][12]] > 1:
                anomalies.append(["Management–фреймы (Тип 0)", "Deauth–фреймов >1% от всех Management–фреймов", "Признак DoS–атаки на клиентов.", "Аномалия"])
            else:
                anomalies.append(["Management–фреймы (Тип 0)", "Deauth–фреймов <1% от всех Management–фреймов", "", "Нормальные значения"])
        if subtype_crypted[0][4] in manage or subtype_crypted[0][5] in manage:
            q = 0
            if subtype_crypted[0][4] in manage:
                q += manage[subtype_crypted[0][4]]
            if subtype_crypted[0][5] in manage:
                q += manage[subtype_crypted[0][5]]
            if q > 10:
                anomalies.append(["Management–фреймы (Тип 0)", "Probe–запросов >10% от всех Management–фреймов", "Активное сканирование сети злоумышленником.", "Аномалия"])
            else:
                anomalies.append(["Management–фреймы (Тип 0)", "Deauth–фреймов <1% от всех Management–фреймов", "", "Нормальные значения"])
    else:
        # Распределение сетевых протоколов
        dist = distribution_of_network_protocols_by_type(df)
        if protocol_names[2] in dist:
            if dist[protocol_names[2]] > 0.01:
                anomalies.append(["Распределение сетевых протоколов", "ICMP >0.1% от всех Data–фреймов", "Может указывать на сканирование сети или атаку ping flood.", "Аномалия"])
            
            else:
                anomalies.append(["Распределение сетевых протоколов", "ICMP >0.1% от всех Data–фреймов", "", "Нормальные значения"])

        dist = distribution_of_network_protocols_by_proto(df)
        if protocol_names[2054] in dist:
            if dist[protocol_names[2054]] > 5:
                anomalies.append(["Распределение сетевых протоколов", "ARP >5% от всех Data–фреймов", "Может свидетельствовать о сетевой петле (ARP–шторм) или атаке ARP–spoofing.", "Аномалия"])
            else:
                anomalies.append(["Распределение сетевых протоколов", "ARP <5% от всех Data–фреймов", "", "Нормальные значения"])
        # Топология сетевого трафика
        toprate = network_traffic_topology(df)
        for key in toprate.keys():
            if toprate[key] >= 50:
                anomalies.append(["Топология сетевого трафика", f"IP {key} занимает {toprate[key]}", "Возможная DDoS–атака или внутреннее заражение.", "Аномалия"])
        # Портовая активность
        port_activity_ = port_activity(df)
        for key in port_activity_.keys():
            anomalies.append(["Топология сетевого трафика", f"Использование нестандартных портов {port_activity_} ", "Может указывать на попытку эксплуатации уязвимостей с помощью вредоносных инструментов (Metasploit, Netcat, трояны).", "Аномалия"])


    return anomalies