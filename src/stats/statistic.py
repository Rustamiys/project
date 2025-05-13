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
        0:	f"Association Request - {types_crypted[0]}",
        1:	f"Association Response - {types_crypted[0]}",
        2:	f"Reassociation Request - {types_crypted[0]}",
        3:	f"Reassociation Response - {types_crypted[0]}",
        4:	f"Probe Request - {types_crypted[0]}",
        5:	f"Probe Response - {types_crypted[0]}",
        6:	f"Timing Advertisement - {types_crypted[0]}",
        7:	f"Reserved - {types_crypted[0]}",
        8:	f"Beacon - {types_crypted[0]}",
        9:	f"ATIM - {types_crypted[0]}",
        10:	f"Disassociation - {types_crypted[0]}",
        11:	f"Authentication - {types_crypted[0]}",
        12:	f"Deauthentication - {types_crypted[0]}",
        13:	f"Action - {types_crypted[0]}",
        14:	f"Action No Ack - {types_crypted[0]}",
        15:	f"Reserved - {types_crypted[0]}"
    },
    1:{
        0:	f"Reserved - {types_crypted[1]}",
        1:	f"RTS (Request To Send) - {types_crypted[1]}",
        2:	f"CTS (Clear To Send) - {types_crypted[1]}",
        3:	f"ACK (Acknowledgment) - {types_crypted[1]}",
        4:	f"CF-End - {types_crypted[1]}",
        5:	f"CF-End + CF-ACK - {types_crypted[1]}",
        6:	f"Control Wrapper - {types_crypted[1]}",
        7:	f"Block Ack Request (BAR) - {types_crypted[1]}",
        8:	f"Block Ack (BA) - {types_crypted[1]}",
        9:	f"PS-Poll - {types_crypted[1]}",
        10:	f"RTS (повторно зарезерв.) - {types_crypted[1]}",
        11:	f"(RTS тоже, или QoS+Ctrl) - {types_crypted[1]}",
        12: f"Reserve - {types_crypted[1]}",
        13: f"Reserved - {types_crypted[1]}",
        14: f"Reserved - {types_crypted[1]}",
        15: f"Reserved - {types_crypted[1]}",
    },
    2:{
        0:	f"Data - {types_crypted[2]}",
        1:	f"Data + CF-ACK - {types_crypted[2]}",
        2:	f"Data + CF-Poll - {types_crypted[2]}",
        3:	f"Data + CF-ACK +\n CF-Poll - {types_crypted[2]}",
        4:	f"Null Data (no data,\n just control) - {types_crypted[2]}",
        5:	f"CF-ACK (no data) - {types_crypted[2]}",
        6:	f"CF-Poll (no data) - {types_crypted[2]}",
        7:	f"CF-ACK + CF-Poll\n (no data) - {types_crypted[2]}",
        8:	f"QoS Data - {types_crypted[2]}",
        9:	f"QoS Data +\n CF-ACK - {types_crypted[2]}",
        10:	f"QoS Data +\n CF-Poll - {types_crypted[2]}",
        11:	f"QoS Data +\n CF-ACK + CF-Poll - {types_crypted[2]}",
        12:	f"QoS Null \n(QoS control only) - {types_crypted[2]}",
        13: f"Reserved - {types_crypted[2]}",
        14: f"Reserved - {types_crypted[2]}",
        15:	f"Reserved - {types_crypted[2]}"
    },
    3:{
        0: f"Reserved - {types_crypted[3]}",
        1: f"Reserved - {types_crypted[3]}",
        2: f"Reserved - {types_crypted[3]}",
        3: f"Reserved - {types_crypted[3]}",
        4: f"Reserved - {types_crypted[3]}",
        5: f"Reserved - {types_crypted[3]}",
        6: f"Reserved - {types_crypted[3]}",
        7: f"Reserved - {types_crypted[3]}",
        8: f"Reserved - {types_crypted[3]}",
        9: f"Reserved - {types_crypted[3]}",
        10: f"Reserved - {types_crypted[3]}",
        11: f"Reserved - {types_crypted[3]}",
        12: f"Reserved - {types_crypted[3]}",
        13: f"Reserved - {types_crypted[3]}",
        14: f"Reserved - {types_crypted[3]}",
        15:	f"Reserved - {types_crypted[3]}"
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
    interval = round(total_range / bin_count)
    if interval <= 0:
        interval = 1
    print(min_time, max_time + interval, interval)
    bins = np.arange(min_time, max_time + interval, interval)
    labels = pd.to_datetime(bins[:-1], unit='s').strftime('%H:%M:%S')

    df['time_bin'] = pd.cut(df['time'], bins=bins, labels=labels, include_lowest=True)
    df_grouped = df.groupby('time_bin')['len'].sum().reset_index(name='value')
    df_grouped['value'] = (df_grouped['value'] / (1024 * 1024)).round(3)
    return df_grouped, "Размер пакетов"


def get_dict_by_count_time(df):
    min_time = df['time'].min()
    max_time = df['time'].max()
    total_range = max_time - min_time
    bin_count = 20
    interval = round(total_range / bin_count)
    if interval <= 0:
        interval = 1
    
    bins = np.arange(min_time, max_time + interval, interval)
    labels = pd.to_datetime(bins[:-1], unit='s').strftime('%H:%M:%S')

    df['time_bin'] = pd.cut(df['time'], bins=bins, labels=labels, include_lowest=True)
    df_grouped = df.groupby('time_bin').size().reset_index(name='value')

    return df_grouped, "Количество пакетов"

def get_pie_subtype_count(df):
    dt = df["type"].value_counts().to_dict()
    return dt, ""

def get_pie_subtype_size(df):
    dt = (df.groupby('type')['len'].sum() / (1024  * 1024)).to_dict()
    dt = {k: round(v, 3) for k, v in dt.items()}
    return dt, "Mb"