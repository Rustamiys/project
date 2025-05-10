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
        0:	"Association Request",
        1:	"Association Response",
        2:	"Reassociation Request",
        3:	"Reassociation Response",
        4:	"Probe Request",
        5:	"Probe Response",
        6:	"Timing Advertisement",
        7:	"Reserved",
        8:	"Beacon",
        9:	"ATIM",
        10:	"Disassociation",
        11:	"Authentication",
        12:	"Deauthentication",
        13:	"Action",
        14:	"Action No Ack",
        15:	"Reserved"
    },
    1:{
        0:	"Reserved",
        1:	"RTS (Request To Send)",
        2:	"CTS (Clear To Send)",
        3:	"ACK (Acknowledgment)",
        4:	"CF-End",
        5:	"CF-End + CF-ACK",
        6:	"Control Wrapper",
        7:	"Block Ack Request (BAR)",
        8:	"Block Ack (BA)",
        9:	"PS-Poll",
        10:	"RTS (повторно зарезерв.)",
        11:	"(RTS тоже, или QoS+Ctrl)",
        12: "Reserved",
        13: "Reserved",
        14: "Reserved",
        15: "Reserved",
    },
    2:{
        0:	"Data",
        1:	"Data + CF-ACK",
        2:	"Data + CF-Poll",
        3:	"Data + CF-ACK +\n CF-Poll",
        4:	"Null Data (no data,\n just control)",
        5:	"CF-ACK (no data)",
        6:	"CF-Poll (no data)",
        7:	"CF-ACK + CF-Poll\n (no data)",
        8:	"QoS Data",
        9:	"QoS Data +\n CF-ACK",
        10:	"QoS Data +\n CF-Poll",
        11:	"QoS Data +\n CF-ACK + CF-Poll",
        12:	"QoS Null \n(QoS control only)",
        13: "Reserved",
        14: "Reserved",
        15:	"Reserved"
    },
    3:{
        0: "Reserved",
        1: "Reserved",
        2: "Reserved",
        3: "Reserved",
        4: "Reserved",
        5: "Reserved",
        6: "Reserved",
        7: "Reserved",
        8: "Reserved",
        9: "Reserved",
        10: "Reserved",
        11: "Reserved",
        12: "Reserved",
        13: "Reserved",
        14: "Reserved",
        15:	"Reserved"
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
    dt = df["type"].value_counts().to_dict()
    named_counts = {}
    for protocol_num, count in dt.items():
        # Берем имя из словаря, если есть, иначе оставляем число как строку
        protocol_name = protocol_names.get(protocol_num, str(protocol_num))
        named_counts[protocol_name] = count
    return named_counts, "Mb"

def get_pie_type_count(df):
    dt = df["type"].value_counts().to_dict()
    named_counts = {}
    for protocol_num, count in dt.items():
        # Берем имя из словаря, если есть, иначе оставляем число как строку
        protocol_name = protocol_names.get(protocol_num, str(protocol_num))
        named_counts[protocol_name] = count
    return named_counts, ""

def get_pie_type_count_crypted(df):
    dt = df["type"].value_counts().to_dict()
    named_counts = {}
    for protocol_num, count in dt.items():
        # Берем имя из словаря, если есть, иначе оставляем число как строку
        protocol_name = types_crypted.get(protocol_num, str(protocol_num))
        named_counts[protocol_name] = count
    return named_counts, ""

def get_pie_type_size_crypted(df):
    dt = df.groupby('type')['len'].sum().to_dict()
    named_counts = {}
    for protocol_num, size in dt.items():
        # Берем имя из словаря, если есть, иначе оставляем число как строку
        protocol_name = types_crypted.get(protocol_num, str(protocol_num))
        named_counts[protocol_name] = size / (1024 * 1024)
    return named_counts, "Mb"

def get_pie_proto_count(df):
    dt = df["proto"].value_counts().to_dict()
    named_counts = {}
    for protocol_num, count in dt.items():
        # Берем имя из словаря, если есть, иначе оставляем число как строку
        protocol_name = protocol_names.get(protocol_num, str(protocol_num))
        named_counts[protocol_name] = count
    return named_counts, ""

def get_pie_proto_size(df):
    dt = df["proto"].value_counts().to_dict()
    named_counts = {}
    for protocol_num, count in dt.items():
        # Берем имя из словаря, если есть, иначе оставляем число как строку
        protocol_name = protocol_names.get(protocol_num, str(protocol_num))
        named_counts[protocol_name] = count
    return named_counts, "Mb"

def get_dict_by_size_time(df):
    min_time = df['time'].min()
    max_time = df['time'].max()
    total_range = max_time - min_time
    bin_count = 20
    interval = round(total_range / bin_count)
    if interval <= 0:
        interval = 1
    print(min_time, max_time + interval, interval)
    bins = np.arange(min_time, max_time + interval, interval)
    labels = pd.to_datetime(bins[:-1], unit='s').strftime('%H:%M:%S')

    df['time_bin'] = pd.cut(df['time'], bins=bins, labels=labels, include_lowest=True)
    df_grouped = df.groupby('time_bin')['len'].sum().reset_index(name='value')
    df_grouped['value'] = df_grouped['value'] / (1024 * 1024)
    return df_grouped, "Размер пакетов"


def get_dict_by_count_time(df):
    min_time = df['time'].min()
    max_time = df['time'].max()
    total_range = max_time - min_time
    bin_count = 20
    interval = round(total_range / bin_count)
    if interval <= 0:
        interval = 1
    print(min_time, max_time + interval, interval)
    
    bins = np.arange(min_time, max_time + interval, interval)
    labels = pd.to_datetime(bins[:-1], unit='s').strftime('%H:%M:%S')

    df['time_bin'] = pd.cut(df['time'], bins=bins, labels=labels, include_lowest=True)
    df_grouped = df.groupby('time_bin').size().reset_index(name='value')

    return df_grouped, "Количество пакетов"

def get_pie_subtype_count(df):
    dt = df["type"].value_counts().to_dict()
    named_counts = {}
    for protocol_num, count in dt.items():
        # Берем имя из словаря, если есть, иначе оставляем число как строку
        protocol_name = types_crypted.get(protocol_num, str(protocol_num))
        named_counts[protocol_name] = count
    return named_counts, ""

def get_pie_subtype_size(df):
    dt = df.groupby('type')['len'].sum().to_dict()
    named_counts = {}
    for protocol_num, size in dt.items():
        # Берем имя из словаря, если есть, иначе оставляем число как строку
        protocol_name = types_crypted.get(protocol_num, str(protocol_num))
        named_counts[protocol_name] = size / (1024 * 1024)
    return named_counts, "Mb"