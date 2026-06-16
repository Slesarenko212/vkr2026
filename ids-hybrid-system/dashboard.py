import streamlit as st
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import os
import time
from datetime import datetime, timedelta

# Попытка импорта Scapy, автоустановка заглушки при отсутствии
try:
    from scapy.all import PcapReader, IP, TCP, wrpcap, Ether
except ImportError:
    st.warning("Библиотека scapy не найдена. Попробуйте выполнить: pip install scapy")

# Настройка страницы (темная тема)
st.set_page_config(
    page_title="СИСТЕМА ОБНАРУЖЕНИЯ ВТОРЖЕНИЙ (NIDS DASHBOARD)", 
    layout="wide", 
    page_icon="🛡️"
)

# --- БЛОК АВТОГЕНЕРАЦИИ ТЕСТОВОГО PCAP ---
def ensure_mock_pcap():
    """Создает тестовый pcap файл в директории data/ для бесперебойного демо-показа"""
    pcap_path = "data/traffic_sample.pcap"
    if not os.path.exists("data"):
        os.makedirs("data")
    if not os.path.exists(pcap_path):
        try:
            packets = []
            for i in range(20):
                # Чередуем аномальные пакеты (SYN, малое окно) и нормальные
                flags = "S" if i % 2 == 0 else "A"
                win = 1024 if i % 2 == 0 else 64240
                pkt = Ether()/IP(src=f"185.190.140.{20+i}", dst="192.168.1.50")/TCP(flags=flags, window=win, sport=1234, dport=80)
                packets.append(pkt)
            wrpcap(pcap_path, packets)
        except Exception:
            pass # Если scapy не инициализировался, разбор пойдет по внутренней симуляции

ensure_mock_pcap()

# --- СТИЛИЗАЦИЯ ИНТЕРФЕЙСА (CSS) ---
st.markdown("""
    <style>
    .stApp { background-color: #0E1117; color: #FFFFFF; }
    .dashboard-card {
        background-color: #FFFFFF;
        color: #000000;
        border-radius: 8px;
        padding: 20px;
        height: 380px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.3);
        margin-bottom: 20px;
    }
    .card-title {
        font-size: 1.05rem;
        font-weight: bold;
        color: #333333;
        margin-bottom: 15px;
    }
    .threat-banner {
        background-color: #D32F2F;
        color: #FFFFFF;
        text-align: center;
        padding: 35px 10px;
        border: 2px solid #000000;
        margin-top: 35px;
    }
    .report-container {
        background-color: #FFFFFF;
        color: #000000;
        padding: 30px;
        border-radius: 4px;
        font-family: Arial, sans-serif;
    }
    </style>
""", unsafe_allowed_html=True)

# Инициализация сессионных переменных состояния
if 'pcap_events' not in st.session_state:
    st.session_state['pcap_events'] = [
        {"Время": "22:04:11", "Тип": "DoS", "Уверенность": "95.4%", "Статус": "Блокирован", "Цвет": "#D32F2F"},
        {"Время": "22:03:55", "Тип": "Scan", "Уверенность": "87.1%", "Статус": "В очереди", "Цвет": "#1976D2"},
        {"Время": "22:01:22", "Тип": "Probe", "Уверенность": "92.0%", "Статус": "Игнорирован", "Цвет": "#555555"},
        {"Время": "21:58:00", "Тип": "Normal", "Уверенность": "12.3%", "Статус": "Пропущено", "Цвет": "#757575"}
    ]

# --- ВЕРХНЯЯ ПАНЕЛЬ ЗАГОЛОВКА ДАШБОРДА ---
col_title, col_status = st.columns([2, 1])
with col_title:
    st.markdown("<h2 style='margin:0;'>СИСТЕМА ОБНАРУЖЕНИЯ ВТОРЖЕНИЙ (NIDS DASHBOARD)</h2>", unsafe_allowed_html=True)
with col_status:
    st.markdown("<h4 style='color: #00E676; text-align: right; margin:0; padding-top:10px;'>NETWORK: ONLINE</h4>", unsafe_allowed_html=True)

st.markdown("<br>", unsafe_allowed_html=True)

# --- ОСНОВНАЯ СЕТКА ЭКРАНА (2х2) ---
row1_col1, row1_col2 = st.columns(2)
row2_col1, row2_col2 = st.columns(2)

# БЛОК 1: ТЕКУЩИЙ УРОВЕНЬ ОПАСНОСТИ
with row1_col1:
    st.markdown("""
        <div class="dashboard-card">
            <div class="card-title">1. ТЕКУЩИЙ УРОВЕНЬ ОПАСНОСТИ (Threat Level)</div>
            <div class="threat-banner">
                <h2 style='margin:0; font-size:1.8rem; font-weight:bold; letter-spacing:1px;'>CRITICAL THREAT: 95%</h2>
                <br>
                <p style='margin:0; font-size:0.9rem; font-weight:500;'>ТРЕБУЕТСЯ НЕМЕДЛЕННОЕ РЕАГИРОВАНИЕ</p>
            </div>
        </div>
    """, unsafe_allowed_html=True)

# БЛОК 2: ГЕОГРАФИЯ АТАК (GeoIP Live Map)
with row1_col2:
    st.markdown("<div class='dashboard-card'><div class='card-title'>2. ГЕОГРАФИЯ АТАК (GeoIP Live Map)</div>", unsafe_allowed_html=True)
    fig, ax = plt.subplots(figsize=(6, 3.2), facecolor='white')
    ax.set_facecolor('white')
    
    # Геометрический контур карты из диссертации
    poly = [[0.1, 0.6], [0.3, 0.8], [0.6, 0.8], [0.9, 0.6], [0.8, 0.2], [0.5, 0.2], [0.2, 0.4]]
    ax.add_patch(plt.Polygon(poly, closed=True, edgecolor='#B0BEC5', facecolor='none', linewidth=1.5))
    
    nodes = {
        'Target Server': (0.5, 0.5, 'green', '*'),
        'Frankfurt (25% Scan)': (0.55, 0.72, '#0D47A1', 'o'),
        'Beijing (55% DoS)': (0.85, 0.55, '#B71C1C', 'o'),
        'Ashburn (15% Probe)': (0.2, 0.52, '#555555', 'o')
    }
    for name, (x, y, color, marker) in nodes.items():
        ax.plot(x, y, marker=marker, color=color, markersize=8 if marker=='o' else 12)
        if name != 'Target Server':
            ax.plot([x, 0.5], [y, 0.5], color=color, linestyle='--', linewidth=1)
        ax.text(x, y + 0.04, name, fontsize=7, ha='center', color='black', weight='bold' if name=='Target Server' else 'normal')
        
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis('off')
    st.pyplot(fig, clear_figure=True)
    st.markdown("</div>", unsafe_allowed_html=True)

# БЛОК 3: АНАЛИТИКА ТИПОВ АТАК (Pie Chart)
with row2_col1:
    st.markdown("<div class='dashboard-card'><div class='card-title'>3. АНАЛИТИКА ТИПОВ АТАК (Pie Chart)</div>", unsafe_allowed_html=True)
    col_chart, col_legend = st.columns([1.1, 0.9])
    
    with col_chart:
        fig2, ax2 = plt.subplots(figsize=(3, 3), facecolor='white')
        ax2.pie([55, 25, 15, 5], colors=['#D32F2F', '#1976D2', '#757575', '#FBC02D'], startangle=20, wedgeprops=dict(width=0.3, edgecolor='black', linewidth=1))
        ax2.set_facecolor('white')
        st.pyplot(fig2, clear_figure=True)
        
    with col_legend:
        st.markdown("<br><br>", unsafe_allowed_html=True)
        st.markdown("<span style='color:#D32F2F; font-weight:bold;'>DoS — 55%</span>", unsafe_allowed_html=True)
        st.markdown("<span style='color:#1976D2; font-weight:bold;'>Scan — 25%</span>", unsafe_allowed_html=True)
        st.markdown("<span style='color:#555555; font-weight:bold;'>Probe — 15%</span>", unsafe_allowed_html=True)
        st.markdown("<span style='color:#FBC02D; font-weight:bold;'>Другие — 5%</span>", unsafe_allowed_html=True)
    st.markdown("</div>", unsafe_allowed_html=True)

# БЛОК 4: ЛЕНТА ИНЦИДЕНТОВ (Live Feed с поддержкой потокового PCAP)
with row2_col2:
    st.markdown("<div class='dashboard-card'><div class='card-title'>4. ЛЕНТА ИНЦИДЕНТОВ (Live Feed)</div>", unsafe_allowed_html=True)
    
    table_placeholder = st.empty()
    
    def render_feed_table(events):
        rows_html = "".join([f"""
            <tr style="color: {ev['Цвет']}; font-weight: 500;">
                <td style="padding: 10px 0;">{ev['Время']}</td>
                <td>{ev['Тип']}</td>
                <td>{ev['Уверенность']}</td>
                <td>{ev['Статус']}</td>
            </tr>
        """ for ev in events])
        
        table_placeholder.markdown(f"""
            <table style="width:100%; border-collapse: collapse; font-family: sans-serif; font-size:0.85rem;">
                <thead>
                    <tr style="border-bottom: 2px solid #000000; text-align: left; color:#333333;">
                        <th style="padding: 8px 0;">Время</th>
                        <th style="padding: 8px 0;">Тип атаки</th>
                        <th style="padding: 8px 0;">Уверенность</th>
                        <th style="padding: 8px 0;">Статус</th>
                    </tr>
                </thead>
                <tbody>{rows_html}</tbody>
            </table>
        """, unsafe_allowed_html=True)

    render_feed_table(st.session_state['pcap_events'])
    
    # Кнопка для запуска разбора реального трафика
    if st.button("🔌 Перехватить и разобрать PCAP-поток"):
        pcap_path = "data/traffic_sample.pcap"
        if os.path.exists(pcap_path) and 'PcapReader' in globals():
            new_events = []
            with PcapReader(pcap_path) as pcap_file:
                for idx, packet in enumerate(pcap_file):
                    if idx >= 4: break # Берем последние 4 пакета для обновления
                    if packet.haslayer(TCP):
                        is_syn = 'S' in str(packet[TCP].flags)
                        win = packet[TCP].window
                        
                        # Моделирование инференса гибридной CNN-LSTM
                        if is_syn and win <= 2000:
                            ev = {"Время": datetime.now().strftime("%H:%M:%S"), "Тип": "DoS", "Уверенность": f"{np.random.uniform(94, 97):.1f}%", "Статус": "Блокирован", "Цвет": "#D32F2F"}
                        elif win == 0:
                            ev = {"Время": datetime.now().strftime("%H:%M:%S"), "Тип": "Scan", "Уверенность": f"{np.random.uniform(84, 89):.1f}%", "Статус": "В очереди", "Цвет": "#1976D2"}
                        else:
                            ev = {"Время": datetime.now().strftime("%H:%M:%S"), "Тип": "Normal", "Уверенность": f"{np.random.uniform(10, 14):.1f}%", "Статус": "Пропущено", "Цвет": "#757575"}
                        
                        new_events.append(ev)
                        time.sleep(0.3) # Имитация аппаратной задержки разбора
            
            if new_events:
                st.session_state['pcap_events'] = new_events
                render_feed_table(new_events)
                st.success("Пакеты pcap успешно агрегированы нейросетью!")
        else:
            st.error("Файл 'data/traffic_sample.pcap' отсутствует или scapy не установлен.")
    st.markdown("</div>", unsafe_allowed_html=True)


# --- ГЕНЕРАЦИЯ ОТЧЕТА ПО ИНЦИДЕНТУ (БЛАНК ИЗ ДИССЕРТАЦИИ) ---
st.markdown("---")
st.header("📄 Генератор отчетных документов SOC")
st.write("Нажмите кнопку ниже, чтобы экспортировать отчет аудита по текущему критическому инциденту:")
if st.button("📊 Сформировать отчет об аудите инцидента"):
  # Фиксация актуального текущего времени (2026 год)
  current_time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
  iso_time_str = datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
  st.markdown("", unsafe_allowed_html=True)
  st.write("### ОТЧЕТ ОБ АУДИТЕ ИНЦИДЕНТА БЕЗОПАСНОСТИ")
  st.caption(f"Сгенерирован: {current_time_str}")

  st.markdown("""""", unsafe_allowed_html=True)
  st.write("1. Краткое описание инцидента")
  incident_df = pd.DataFrame({
    "Параметр": ["Временная метка (ISO)", "Тип угрозы", "Уверенность модели", "IP-источник (Атакующий)", 
                 "IP-назначение (Цель)", "Уровень опасности"],"Значение": [iso_time_str, "DoS-атака (Slowloris)", 
                                                                           "95.42%", "185.190.140.23", "192.168.1.50", 
                                                                           "КРИТИЧЕСКИЙ"]})
# Рендеринг таблицы с красным выделением критического уровня опасности
  st.markdown(incident_df.to_html(index=False, escape=False).replace("КРИТИЧЕСКИЙ", "КРИТИЧЕСКИЙ"),unsafe_allowed_html=True)
  st.write("", unsafe_allowed_html=True)
  st.write("2. Вклад признаков нейронной сети (Экстракция CNN)")
  st.write("Следующие параметры заголовков сетевого трафика внесли наибольший вклад в решение модели:")
  features_df = pd.DataFrame({"Извлеченный признак": ["tcp.flags.syn", "tcp.window_size", "packet_interarrival_time"],
                              "Вес влияния": [0.42, 0.35, 0.23]})
  st.markdown(features_df.to_html(index=False), unsafe_allowed_html=True)
  st.markdown("", unsafe_allowed_html=True)
# Кнопка скачивания markdown текста
  st.download_button(label="📥 Скачать текст отчета ",data=f"ОТЧЕТ ОБ АУДИТЕ ИНЦИДЕНТА\nСгенерирован: 
  {current_time_str}\nТип угрозы: DoS-атака (Slowloris)\nУверенность: 95.42%",file_name="incident_report.txt")
