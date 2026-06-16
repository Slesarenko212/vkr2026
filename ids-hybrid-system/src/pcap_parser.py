import os
import time
from scapy.all import PcapReader, IP, TCP

def stream_pcap_features(pcap_path, delay=0.5):
    """
    Потоковый генератор пакетов из pcap-файла.
    Имитирует сетевой интерфейс (задержка delay) и извлекает признаки.
    """
    if not os.path.exists(pcap_path):
        raise FileNotFoundError(f"Файл {pcap_path} не найден. Поместите его в директорию data/")

    last_timestamp = None

    with PcapReader(pcap_path) as pcap_file:
        for packet in pcap_file:
            #  интересует только IP и TCP трафик (база для атак DoS/Slowloris)
            if packet.haslayer(IP) and packet.haslayer(TCP):
                ip_layer = packet[IP]
                tcp_layer = packet[TCP]

                # 1. Расчет интервала времени между пакетами (packet_interarrival_time)
                current_timestamp = float(packet.time)
                if last_timestamp is None:
                    interarrival_time = 0.0
                else:
                    interarrival_time = current_timestamp - last_timestamp
                last_timestamp = current_timestamp

                # 2. Извлечение флагов (проверка флага SYN для tcp.flags.syn)
                # tcp_layer.flags — это битовая маска (S=SYN, A=ACK, F=FIN, P=PSH)
                is_syn = 1.0 if 'S' in str(tcp_layer.flags) else 0.0

                # 3. Извлечение размера окна (tcp.window_size)
                window_size = float(tcp_layer.window)

                # Формируем словарь метаданных для дашборда
                packet_meta = {
                    "src_ip": ip_layer.src,
                    "dst_ip": ip_layer.dst,
                    "sport": tcp_layer.sport,
                    "dport": tcp_layer.dport,
                    "raw_features": [is_syn, window_size, interarrival_time] 
                }

                # Задержка для плавной визуализации на дашборде
                time.sleep(delay)
                yield packet_meta
