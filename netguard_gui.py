"""
NetGuard — ARP Spoof Detector & Active Defense System
GUI-приложение на базе Flet 0.85+ (Modern Dark Theme)

Архитектура потоков:
  - Основной поток: Flet UI event loop
  - Поток 1 (daemon): sniff() из Scapy — захват ARP-пакетов
  - Поток 2 (daemon): antidote_worker() — рассылка легитимных ARP-ответов
"""

import sys
import subprocess
import re
import threading
import time
import ctypes
import winsound
import queue
import flet as ft

# Flet 0.85+: Padding/Margin/Border/BorderSide доступны через ft напрямую
Padding   = ft.Padding
Margin    = ft.Margin
Border    = ft.Border
BorderSide = ft.BorderSide
from scapy.all import sniff, ARP, conf, Ether, srp1, sendp

# ──────────────────────────────────────────────────
#  ГЛОБАЛЬНОЕ СОСТОЯНИЕ ПРИЛОЖЕНИЯ
# ──────────────────────────────────────────────────
gateway_ip: str | None = None
gateway_mac: str | None = None
selected_iface_name: str | None = None
sniffer_active: bool = False
antidote_active: bool = False
sniff_thread: threading.Thread | None = None
log_queue = queue.Queue()
raw_packet_queue = queue.Queue()

# ──────────────────────────────────────────────────
#  ВСПОМОГАТЕЛЬНЫЕ СЕТЕВЫЕ ФУНКЦИИ
# ──────────────────────────────────────────────────

def get_gateway_ip(iface_name: str | None = None) -> str | None:
    """
    Определяет IP шлюза по умолчанию для выбранного интерфейса.
    """
    try:
        if iface_name:
            for dest, netmask, gateway, interface, output_ip, metric in conf.route.routes:
                if dest == 0 and netmask == 0 and interface == iface_name:
                    if gateway and gateway != "0.0.0.0":
                        return gateway
            return None  # Не перенаправляем на шлюз другого интерфейса
        _, _, gw_ip = conf.route.route("0.0.0.0")
        if gw_ip and gw_ip != "0.0.0.0":
            return gw_ip
    except Exception:
        pass
    return None


def get_mac_from_arp_cache(ip_address: str) -> str | None:
    """Ищет MAC-адрес IP в системном кэше ARP (arp -a)."""
    try:
        output = subprocess.check_output(["arp", "-a"], stderr=subprocess.DEVNULL)
        decoded = output.decode("cp866", errors="ignore")
        for line in decoded.splitlines():
            if ip_address in line:
                m = re.search(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", line)
                if m:
                    return m.group(0).replace("-", ":").lower()
    except Exception:
        pass
    return None


def get_gateway_mac(ip_address: str, iface_name: str) -> str | None:
    """
    Определяет MAC-адрес шлюза.
    Сначала проверяет системный кэш ARP (очень быстро, <50мс).
    Если там нет, пробует разогреть кэш пингом и отправить ARP-запрос Scapy.
    """
    # 1. Сначала ищем в системном кэше (самый быстрый и безопасный способ)
    cached_mac = get_mac_from_arp_cache(ip_address)
    if cached_mac:
        return cached_mac

    # 2. Если в кэше нет, пробуем разогреть пингом
    try:
        subprocess.run(["ping", "-n", "1", "-w", "500", ip_address],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass

    # Сразу после пинга проверяем кэш снова
    cached_mac = get_mac_from_arp_cache(ip_address)
    if cached_mac:
        return cached_mac

    # 3. Как крайняя мера — активный ARP-запрос Scapy srp1
    try:
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_address)
        ans = srp1(pkt, iface=iface_name, timeout=1.5, verbose=False)
        if ans and ARP in ans:
            return ans[ARP].hwsrc.lower()
    except Exception:
        pass

    return None


def get_ip_from_arp_cache(mac_address: str) -> str | None:
    """Ищет IP по MAC-адресу в системном кэше ARP."""
    try:
        mac_norm = mac_address.lower().replace(":", "-")
        output = subprocess.check_output(["arp", "-a"], stderr=subprocess.DEVNULL)
        decoded = output.decode("cp866", errors="ignore")
        for line in decoded.splitlines():
            if mac_norm in line.lower():
                m = re.search(r"((?:[0-9]{1,3}\.){3}[0-9]{1,3})", line)
                if m:
                    return m.group(1)
    except Exception:
        pass
    return None


def ban_attacker(attacker_ip: str):
    """Блокирует IP атакующего через Брандмауэр Windows."""
    try:
        cmd = (
            f'netsh advfirewall firewall add rule '
            f'name="BLOCK_ARP_ATTACKER" dir=in action=block remoteip={attacker_ip}'
        )
        subprocess.run(cmd, shell=True, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass


def cleanup_firewall_rule():
    """Удаляет правило брандмауэра при закрытии приложения."""
    try:
        subprocess.run(
            'netsh advfirewall firewall delete rule name="BLOCK_ARP_ATTACKER"',
            shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
    except Exception:
        pass


def antidote_worker(router_ip: str, real_router_mac: str, iface_name: str):
    """
    Фоновый поток ARP-антидота.
    Каждые 0.5 с рассылает широковещательный ARP-ответ
    с легитимным MAC-адресом роутера.
    """
    global antidote_active
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2,
        psrc=router_ip,
        hwsrc=real_router_mac,
        pdst="255.255.255.255"
    )
    while antidote_active:
        try:
            sendp(pkt, iface=iface_name, verbose=False)
        except Exception:
            pass
        time.sleep(0.5)


# ──────────────────────────────────────────────────
#  FLET ГЛАВНАЯ ФУНКЦИЯ
# ──────────────────────────────────────────────────

def main(page: ft.Page):
    global gateway_ip, gateway_mac, selected_iface_name
    global sniffer_active, antidote_active, sniff_thread

    # ── Настройки окна ──────────────────────────────
    page.title = "NetGuard — ARP Spoof Detector"
    page.theme_mode = ft.ThemeMode.DARK
    page.bgcolor = "#0A0E1A"
    page.window.width = 920
    page.window.height = 700
    page.window.min_width = 750
    page.window.min_height = 560
    page.padding = 0

    # ── Проверка прав администратора ─────────────────
    is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())

    # ── Цветовая палитра ─────────────────────────────
    COLOR_BG           = "#0A0E1A"
    COLOR_PANEL        = "#111827"
    COLOR_BORDER       = "#1E2D45"
    COLOR_ACCENT       = "#00D4FF"
    COLOR_ACCENT_DIM   = "#003D5C"
    COLOR_SUCCESS      = "#00E676"
    COLOR_SUCCESS_BG   = "#0A2A1A"
    COLOR_DANGER       = "#FF1744"
    COLOR_DANGER_DIM   = "#4A0010"
    COLOR_TEXT_DIM     = "#607090"
    COLOR_TEXT         = "#C8D8F0"

    # ──────────────────────────────────────────────────
    #  REF-ССЫЛКИ НА КОНТРОЛЫ ДЛЯ ОБНОВЛЕНИЯ ИЗ ПОТОКОВ
    # ──────────────────────────────────────────────────
    iface_dropdown = ft.Ref[ft.Dropdown]()
    start_btn      = ft.Ref[ft.Button]()
    btn_stop_antidote = ft.Ref[ft.Button]()
    status_text    = ft.Ref[ft.Text]()
    router_ip_text = ft.Ref[ft.Text]()
    router_mac_text= ft.Ref[ft.Text]()
    status_panel   = ft.Ref[ft.Container]()
    log_list       = ft.Ref[ft.ListView]()

    # ──────────────────────────────────────────────────
    #  ЛОГИРОВАНИЕ В UI (Буферизованное)
    # ──────────────────────────────────────────────────
    def add_log(text: str, color: str = COLOR_TEXT, bold: bool = False):
        """
        Add log parameters to the queue for background dispatcher to process.
        """
        global log_queue
        ts = time.strftime("%H:%M:%S")
        log_queue.put({"text": f"[{ts}]  {text}", "color": color, "bold": bold})

    async def update_logs_ui(new_controls):
        if log_list.current:
            log_list.current.controls.extend(new_controls)
            if len(log_list.current.controls) > 200:
                del log_list.current.controls[:-200]
            log_list.current.update()

    def log_dispatcher():
        global log_queue
        while True:
            try:
                time.sleep(0.1)
                if not log_list.current or log_queue.empty():
                    continue

                new_controls = []
                while not log_queue.empty():
                    item = log_queue.get_nowait()
                    new_controls.append(
                        ft.Text(
                            item["text"],
                            color=item["color"],
                            size=11,
                            weight=ft.FontWeight.BOLD if item["bold"] else ft.FontWeight.NORMAL,
                            selectable=True,
                        )
                    )
                    log_queue.task_done()

                if new_controls:
                    page.run_task(update_logs_ui, new_controls)
            except Exception:
                pass

    threading.Thread(target=log_dispatcher, daemon=True).start()

    # ──────────────────────────────────────────────────
    #  РЕЖИМ ТРЕВОГИ
    # ──────────────────────────────────────────────────
    async def trigger_alert_ui(attacker_mac: str, attacker_ip: str | None):
        """
        Визуальная и звуковая тревога при обнаружении атаки.
        Вызывается асинхронно в основном потоке Flet.
        """
        status_panel.current.bgcolor = COLOR_DANGER_DIM
        status_panel.current.border = Border(
            top=BorderSide(2, COLOR_DANGER),
            right=BorderSide(2, COLOR_DANGER),
            bottom=BorderSide(2, COLOR_DANGER),
            left=BorderSide(2, COLOR_DANGER),
        )
        status_text.current.value = "⚠  ВНИМАНИЕ: ОБНАРУЖЕНА КИБЕРАТАКА!"
        status_text.current.color = COLOR_DANGER
        status_text.current.size  = 20

        page.update()

        threading.Thread(target=winsound.Beep, args=(2000, 1000), daemon=True).start()

        add_log("=" * 58, COLOR_DANGER, bold=True)
        add_log("ОБНАРУЖЕН ARP-SPOOFING РОУТЕРА!", COLOR_DANGER, bold=True)
        add_log(f"Шлюз (IP):       {gateway_ip}", COLOR_DANGER)
        add_log(f"Эталонный MAC:   {gateway_mac}", COLOR_DANGER)
        add_log(f"Атакующий MAC:   {attacker_mac}", COLOR_DANGER)
        if attacker_ip:
            add_log(f"IP атакующего:   {attacker_ip}", COLOR_DANGER)
            add_log(f"[+] Запущена функция БАНА для IP: {attacker_ip}", COLOR_DANGER, bold=True)
        add_log("=" * 58, COLOR_DANGER, bold=True)

    async def activate_antidote_ui():
        """Активирует оранжевую кнопку остановки антидота в UI."""
        if btn_stop_antidote.current:
            btn_stop_antidote.current.disabled = False
            btn_stop_antidote.current.bgcolor = ft.Colors.ORANGE_800
            btn_stop_antidote.current.content = ft.Row(
                [ft.Icon(ft.Icons.STOP, size=16, color=ft.Colors.WHITE),
                 ft.Text("💊 ОСТАНОВИТЬ АНТИДОТ", size=14, weight=ft.FontWeight.BOLD, color=ft.Colors.WHITE)],
                spacing=8, tight=True
            )
            page.update()

    async def restore_start_button_ui():
        """Возвращает кнопку защиты в исходное состояние при ошибке инициализации."""
        if start_btn.current:
            start_btn.current.disabled = False
            start_btn.current.content = ft.Row(
                [ft.Icon(ft.Icons.SHIELD, size=16), ft.Text("ВКЛЮЧИТЬ ЗАЩИТУ", size=14, weight=ft.FontWeight.BOLD)],
                spacing=8, tight=True
            )
            start_btn.current.bgcolor = COLOR_ACCENT_DIM
            page.update()

    async def update_protection_active_ui(gw_ip: str, gw_mac: str):
        """Обновляет статус и элементы управления при успешном включении защиты."""
        if router_ip_text.current:
            router_ip_text.current.value  = f"IP роутера:   {gw_ip}"
        if router_mac_text.current:
            router_mac_text.current.value = f"MAC эталон:  {gw_mac}"
        if status_text.current:
            status_text.current.value     = "🛡  Сеть под защитой"
            status_text.current.color     = COLOR_SUCCESS
            status_text.current.size      = 22
        if status_panel.current:
            status_panel.current.bgcolor  = COLOR_SUCCESS_BG
            status_panel.current.border   = Border(
                top=BorderSide(2, COLOR_SUCCESS),
                right=BorderSide(2, COLOR_SUCCESS),
                bottom=BorderSide(2, COLOR_SUCCESS),
                left=BorderSide(2, COLOR_SUCCESS),
            )
        
        if start_btn.current:
            start_btn.current.disabled = False
            start_btn.current.content = ft.Row(
                [ft.Icon(ft.Icons.SHIELD, size=16, color=ft.Colors.WHITE),
                 ft.Text("🛑 ОСТАНОВИТЬ ЗАЩИТУ", size=14, weight=ft.FontWeight.BOLD, color=ft.Colors.WHITE)],
                spacing=8, tight=True
            )
            start_btn.current.bgcolor = COLOR_DANGER
            start_btn.current.color = ft.Colors.WHITE
        
        page.update()

    async def reset_protection_ui():
        """Сбрасывает все UI-элементы в состояние ожидания."""
        if status_text.current:
            status_text.current.value     = "⬤  ОЖИДАНИЕ ЗАПУСКА"
            status_text.current.color     = COLOR_TEXT_DIM
            status_text.current.size      = 22
        if status_panel.current:
            status_panel.current.bgcolor  = COLOR_PANEL
            status_panel.current.border   = Border(
                top=BorderSide(2, COLOR_BORDER),
                right=BorderSide(2, COLOR_BORDER),
                bottom=BorderSide(2, COLOR_BORDER),
                left=BorderSide(2, COLOR_BORDER),
            )
        if router_ip_text.current:
            router_ip_text.current.value  = "IP роутера:   —"
        if router_mac_text.current:
            router_mac_text.current.value = "MAC эталон:  —"
        
        if start_btn.current:
            start_btn.current.content = ft.Row(
                [ft.Icon(ft.Icons.SHIELD, size=16, color=COLOR_ACCENT),
                 ft.Text("ВКЛЮЧИТЬ ЗАЩИТУ", size=14, weight=ft.FontWeight.BOLD, color=COLOR_ACCENT)],
                spacing=8, tight=True
            )
            start_btn.current.bgcolor = COLOR_ACCENT_DIM
            start_btn.current.color = COLOR_ACCENT
        
        if btn_stop_antidote.current:
            btn_stop_antidote.current.disabled = True
            btn_stop_antidote.current.bgcolor = None
            btn_stop_antidote.current.content = ft.Row(
                [ft.Icon(ft.Icons.STOP, size=16, color=COLOR_TEXT_DIM),
                 ft.Text("Антидот выключен", size=14, weight=ft.FontWeight.BOLD, color=COLOR_TEXT_DIM)],
                spacing=8, tight=True
            )
        page.update()

    # ──────────────────────────────────────────────────
    #  SCAPY ARP CALLBACK
    # ──────────────────────────────────────────────────
    # ──────────────────────────────────────────────────
    #  SCAPY ARP CALLBACK (Producer)
    # ──────────────────────────────────────────────────
    def arp_callback(packet):
        """
        Сверхбыстрый колбэк (Producer). Помещает сырой ARP-пакет в очередь.
        """
        if ARP in packet:
            raw_packet_queue.put(packet[ARP])

    def packet_analyzer_worker():
        """
        Фоновый поток-консьюмер. Извлекает перехваченные пакеты из raw_packet_queue
        и выполняет их детальный анализ, логирование и запуск тревоги.
        """
        global gateway_ip, gateway_mac, selected_iface_name, antidote_active, sniffer_active
        while sniffer_active:
            try:
                # Читаем пакет из очереди с таймаутом, чтобы не зависать при остановке защиты
                arp = raw_packet_queue.get(timeout=1.0)
            except queue.Empty:
                continue

            try:
                op_code = arp.op
                src_ip  = arp.psrc
                src_mac = arp.hwsrc
                dst_ip  = arp.pdst

                if op_code == 1:
                    add_log(
                        f"[ЗАПРОС]  Кто {dst_ip}? → спросил {src_ip} ({src_mac})",
                        COLOR_TEXT_DIM
                    )
                elif op_code == 2:
                    add_log(
                        f"[ОТВЕТ]   {src_ip} → MAC: {src_mac}  (для {dst_ip})",
                        COLOR_TEXT
                    )

                    # ── ДЕТЕКТОР ARP-SPOOFING ─────────────────────────
                    if gateway_ip and src_ip == gateway_ip:
                        if src_mac.lower() != gateway_mac.lower():
                            attacker_ip = get_ip_from_arp_cache(src_mac)

                            if attacker_ip:
                                ban_attacker(attacker_ip)

                            # Запускаем ARP-антидот (только один раз)
                            if not antidote_active:
                                antidote_active = True
                                add_log(
                                    "[+] АКТИВИРОВАН ARP-АНТИДОТ: Подавление атаки в локальной сети...",
                                    COLOR_SUCCESS, bold=True
                                )
                                
                                # Активируем кнопку антидота асинхронно
                                page.run_task(activate_antidote_ui)
                                
                                threading.Thread(
                                    target=antidote_worker,
                                    args=(gateway_ip, gateway_mac, selected_iface_name),
                                    daemon=True
                                ).start()

                            # Активируем тревогу в UI асинхронно
                            page.run_task(trigger_alert_ui, src_mac, attacker_ip)
                else:
                    add_log(
                        f"[ИНОЕ op={op_code}]  {src_ip} ({src_mac}) → {dst_ip}",
                        COLOR_TEXT_DIM
                    )
            except Exception as ex:
                add_log(f"[!] Ошибка анализа пакета: {ex}", COLOR_DANGER)
            finally:
                raw_packet_queue.task_done()

    # ──────────────────────────────────────────────────
    #  ОБРАБОТЧИК КНОПКИ АНТИДОТА
    # ──────────────────────────────────────────────────
    def on_stop_antidote(e):
        global antidote_active
        if antidote_active:
            antidote_active = False
            add_log(
                "[-] Фоновый ARP-Антидот принудительно остановлен пользователем. Мониторинг сети продолжается.",
                COLOR_TEXT_DIM
            )
            btn_stop_antidote.current.disabled = True
            btn_stop_antidote.current.bgcolor = None
            btn_stop_antidote.current.content = ft.Row(
                [ft.Icon(ft.Icons.STOP, size=16, color=COLOR_TEXT_DIM),
                 ft.Text("Антидот выключен", size=14, weight=ft.FontWeight.BOLD, color=COLOR_TEXT_DIM)],
                spacing=8, tight=True
            )
            page.update()

    # ──────────────────────────────────────────────────
    #  ЗАПУСК / ОСТАНОВКА ЗАЩИТЫ (обработчик кнопки)
    # ──────────────────────────────────────────────────
    def on_start_protection(e):
        global gateway_ip, gateway_mac, selected_iface_name
        global sniffer_active, antidote_active, sniff_thread

        if sniffer_active:
            # ОСТАНОВКА ВСЕГО
            sniffer_active = False
            antidote_active = False
            cleanup_firewall_rule()
            
            add_log("[-] Защита остановлена пользователем.", COLOR_TEXT_DIM)
            
            # Возвращаем панель статуса
            status_text.current.value     = "⬤  ОЖИДАНИЕ ЗАПУСКА"
            status_text.current.color     = COLOR_TEXT_DIM
            status_text.current.size      = 22
            status_panel.current.bgcolor  = COLOR_PANEL
            status_panel.current.border   = Border(
                top=BorderSide(2, COLOR_BORDER),
                right=BorderSide(2, COLOR_BORDER),
                bottom=BorderSide(2, COLOR_BORDER),
                left=BorderSide(2, COLOR_BORDER),
            )
            router_ip_text.current.value  = "IP роутера:   —"
            router_mac_text.current.value = "MAC эталон:  —"
            
            # Возвращаем кнопку защиты
            start_btn.current.content = ft.Row(
                [ft.Icon(ft.Icons.SHIELD, size=16, color=COLOR_ACCENT),
                 ft.Text("ВКЛЮЧИТЬ ЗАЩИТУ", size=14, weight=ft.FontWeight.BOLD, color=COLOR_ACCENT)],
                spacing=8, tight=True
            )
            start_btn.current.bgcolor = COLOR_ACCENT_DIM
            start_btn.current.color = COLOR_ACCENT
            
            # Возвращаем кнопку антидота
            btn_stop_antidote.current.disabled = True
            btn_stop_antidote.current.bgcolor = None
            btn_stop_antidote.current.content = ft.Row(
                [ft.Icon(ft.Icons.STOP, size=16, color=COLOR_TEXT_DIM),
                 ft.Text("Антидот выключен", size=14, weight=ft.FontWeight.BOLD, color=COLOR_TEXT_DIM)],
                spacing=8, tight=True
            )
            
            page.update()
            return

        if not iface_dropdown.current.value:
            add_log("[!] Сначала выберите сетевой интерфейс!", COLOR_DANGER, bold=True)
            return

        # Блокируем кнопку на время инициализации
        start_btn.current.disabled = True
        start_btn.current.content = ft.Row(
            [ft.ProgressRing(width=16, height=16, stroke_width=2, color=COLOR_ACCENT),
             ft.Text("Инициализация...", size=14, weight=ft.FontWeight.BOLD)],
            spacing=8, tight=True
        )
        start_btn.current.bgcolor = "#1A3A4A"
        page.update()

        def init_and_sniff():
            global gateway_ip, gateway_mac, selected_iface_name
            global sniffer_active, antidote_active

            # 1. Сброс сетевого кэша Scapy
            try:
                conf.route.resync()
            except Exception as ex:
                add_log(f"[!] Не удалось сбросить кэш Scapy: {ex}", COLOR_TEXT_DIM)

            # 2. Микропауза 0.3 сек для обновления таблиц в Windows
            time.sleep(0.3)

            selected_iface_name = iface_dropdown.current.value
            antidote_active     = False

            # 3. Определение IP шлюза
            add_log("[*] Определение IP-адреса шлюза по умолчанию...", COLOR_ACCENT)
            gw_ip = get_gateway_ip(selected_iface_name)
            if not gw_ip:
                add_log("[!] Не удалось определить IP шлюза автоматически.", COLOR_DANGER, bold=True)
                page.run_task(restore_start_button_ui)
                return

            gateway_ip = gw_ip
            add_log(f"[+] Шлюз обнаружен: {gateway_ip}", COLOR_SUCCESS)

            # 4. Определение эталонного MAC шлюза
            add_log(f"[*] Получение эталонного MAC-адреса для {gateway_ip}...", COLOR_ACCENT)
            gw_mac = get_gateway_mac(gateway_ip, selected_iface_name)
            if not gw_mac:
                add_log("[!] Не удалось определить MAC шлюза.", COLOR_DANGER, bold=True)
                page.run_task(restore_start_button_ui)
                return

            gateway_mac = gw_mac
            sniffer_active = True

            # Очищаем старую очередь пакетов перед началом нового сканирования
            while not raw_packet_queue.empty():
                try:
                    raw_packet_queue.get_nowait()
                except Exception:
                    break

            # Запускаем фоновый поток анализа пакетов (Consumer)
            threading.Thread(target=packet_analyzer_worker, daemon=True).start()

            # Обновление UI в главном потоке
            page.run_task(update_protection_active_ui, gateway_ip, gateway_mac)

            add_log(f"[+] Эталонный MAC зафиксирован: {gateway_mac}", COLOR_SUCCESS, bold=True)
            add_log("─" * 58, COLOR_TEXT_DIM)
            add_log("[*] Активный мониторинг ARP-трафика запущен...", COLOR_ACCENT, bold=True)
            add_log("[*] Закройте окно для завершения.", COLOR_TEXT_DIM)
            add_log("─" * 58, COLOR_TEXT_DIM)

            try:
                sniff(
                    iface=selected_iface_name,
                    filter="arp",
                    prn=arp_callback,
                    store=0,
                    count=0,
                    stop_filter=lambda p: not sniffer_active
                )
            except Exception as ex:
                add_log(f"[!] Ошибка Scapy sniff: {ex}", COLOR_DANGER, bold=True)

            # На случай непредвиденного завершения (если sniffer_active еще True)
            if sniffer_active:
                sniffer_active = False
                antidote_active = False
                cleanup_firewall_rule()
                page.run_task(reset_protection_ui)

        sniff_thread = threading.Thread(target=init_and_sniff, daemon=True)
        sniff_thread.start()

    # ──────────────────────────────────────────────────
    #  ЗАКРЫТИЕ ОКНА — АВТООЧИСТКА БРАНДМАУЭРА
    # ──────────────────────────────────────────────────
    def on_window_close(e):
        """
        При закрытии окна удаляет правило BLOCK_ARP_ATTACKER
        из Брандмауэра Windows, чтобы не засорять систему.
        """
        global sniffer_active, antidote_active
        sniffer_active = False
        antidote_active = False
        cleanup_firewall_rule()
        page.window.destroy()

    page.window.on_close = on_window_close

    # ──────────────────────────────────────────────────
    #  СПИСОК ИНТЕРФЕЙСОВ ДЛЯ DROPDOWN ──────────────────
    # ──────────────────────────────────────────────────
    ifaces_list = list(conf.ifaces.values())

    # Поиск рекомендованного интерфейса
    recommended_iface_name = None
    for iface in ifaces_list:
        ip = iface.ip or ""
        desc = iface.description or ""
        
        # Критерии для рекомендации
        starts_with_pref = ip.startswith("192.168.") or ip.startswith("10.")
        has_exclude_word = any(
            word.lower() in desc.lower() 
            for word in ["virtual", "hyper-v", "loopback", "bluetooth"]
        )
        
        if starts_with_pref and not has_exclude_word:
            recommended_iface_name = getattr(iface, "network_name", iface.name)
            break

    dropdown_options = []
    for iface in ifaces_list:
        ip_str = f" [{iface.ip}]" if iface.ip else ""
        iface_key = getattr(iface, "network_name", iface.name)
        if iface_key == recommended_iface_name:
            text = f"⭐ Рекомендуется — {iface.description}{ip_str}"
        else:
            text = f"{iface.description}{ip_str} (Служебный)"
            
        dropdown_options.append(
            ft.dropdown.Option(
                key=iface_key,
                text=text
            )
        )

    # ──────────────────────────────────────────────────
    #  ПОСТРОЕНИЕ UI
    # ──────────────────────────────────────────────────

    # ── Шапка ────────────────────────────────────────
    header = ft.Container(
        content=ft.Row(
            controls=[
                ft.Icon(ft.Icons.SECURITY, color=COLOR_ACCENT, size=32),
                ft.Column(
                    controls=[
                        ft.Text(
                            "NetGuard",
                            size=26,
                            weight=ft.FontWeight.BOLD,
                            color=COLOR_ACCENT,
                        ),
                        ft.Text(
                            "ARP Spoof Detector & Active Defense System",
                            size=11,
                            color=COLOR_TEXT_DIM,
                        ),
                    ],
                    spacing=0,
                ),
            ],
            spacing=12,
        ),
        padding=Padding(left=24, right=24, top=16, bottom=16),
        bgcolor=COLOR_PANEL,
        border=Border(bottom=BorderSide(1, COLOR_BORDER)),
    )

    # ── Панель выбора интерфейса + кнопка ────────────
    control_row = ft.Container(
        content=ft.Row(
            controls=[
                ft.Dropdown(
                    ref=iface_dropdown,
                    label="Сетевой интерфейс",
                    hint_text="Выберите интерфейс для мониторинга...",
                    value=recommended_iface_name,
                    options=dropdown_options,
                    expand=True,
                    bgcolor=COLOR_PANEL,
                    color=COLOR_TEXT,
                    border_color=COLOR_BORDER,
                    focused_border_color=COLOR_ACCENT,
                    label_style=ft.TextStyle(color=COLOR_TEXT_DIM),
                ),
                ft.Button(
                    ref=start_btn,
                    content=ft.Row(
                        controls=[
                            ft.Icon(ft.Icons.SHIELD, size=16, color=COLOR_ACCENT),
                            ft.Text(
                                "ВКЛЮЧИТЬ ЗАЩИТУ",
                                size=14,
                                weight=ft.FontWeight.BOLD,
                                color=COLOR_ACCENT,
                            ),
                        ],
                        spacing=8,
                        tight=True,
                    ),
                    on_click=on_start_protection,
                    bgcolor=COLOR_ACCENT_DIM,
                    color=COLOR_ACCENT,
                    height=52,
                    style=ft.ButtonStyle(
                        shape=ft.RoundedRectangleBorder(radius=8),
                        padding=Padding(left=24, right=24, top=14, bottom=14),
                        overlay_color={"hovered": "#004A6A"},
                    ),
                ),
                ft.Button(
                    ref=btn_stop_antidote,
                    content=ft.Row(
                        controls=[
                            ft.Icon(ft.Icons.STOP, size=16, color=COLOR_TEXT_DIM),
                            ft.Text(
                                "Антидот выключен",
                                size=14,
                                weight=ft.FontWeight.BOLD,
                                color=COLOR_TEXT_DIM,
                            ),
                        ],
                        spacing=8,
                        tight=True,
                    ),
                    on_click=on_stop_antidote,
                    disabled=True,
                    height=52,
                    style=ft.ButtonStyle(
                        shape=ft.RoundedRectangleBorder(radius=8),
                        padding=Padding(left=24, right=24, top=14, bottom=14),
                    ),
                ),
            ],
            spacing=16,
        ),
        padding=Padding(left=24, right=24, top=14, bottom=14),
        bgcolor=COLOR_PANEL,
        border=Border(bottom=BorderSide(1, COLOR_BORDER)),
    )

    # ── Панель статуса (центральная) ─────────────────
    status_panel_widget = ft.Container(
        ref=status_panel,
        content=ft.Column(
            controls=[
                ft.Text(
                    ref=status_text,
                    value="⬤  ОЖИДАНИЕ ЗАПУСКА",
                    size=22,
                    weight=ft.FontWeight.BOLD,
                    color=COLOR_TEXT_DIM,
                ),
                ft.Divider(height=8, color="transparent"),
                ft.Row(
                    controls=[
                        ft.Icon(ft.Icons.ROUTER, color=COLOR_TEXT_DIM, size=16),
                        ft.Text(
                            ref=router_ip_text,
                            value="IP роутера:   —",
                            size=13,
                            color=COLOR_TEXT_DIM,
                        ),
                    ],
                    spacing=8,
                ),
                ft.Row(
                    controls=[
                        ft.Icon(ft.Icons.FINGERPRINT, color=COLOR_TEXT_DIM, size=16),
                        ft.Text(
                            ref=router_mac_text,
                            value="MAC эталон:  —",
                            size=13,
                            color=COLOR_TEXT_DIM,
                        ),
                    ],
                    spacing=8,
                ),
            ],
            spacing=4,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
        ),
        padding=Padding(left=32, right=32, top=20, bottom=20),
        bgcolor=COLOR_PANEL,
        border=Border(
            top=BorderSide(2, COLOR_BORDER),
            right=BorderSide(2, COLOR_BORDER),
            bottom=BorderSide(2, COLOR_BORDER),
            left=BorderSide(2, COLOR_BORDER),
        ),
        border_radius=12,
        margin=Margin(left=24, right=24, top=10, bottom=0),
        animate=ft.Animation(400, ft.AnimationCurve.EASE_IN_OUT),
    )

    # ── Лог-панель (нижняя часть) ─────────────────────
    log_panel_widget = ft.Container(
        content=ft.Column(
            controls=[
                ft.Row(
                    controls=[
                        ft.Icon(ft.Icons.TERMINAL, color=COLOR_TEXT_DIM, size=14),
                        ft.Text(
                            "  ARP Log Stream",
                            size=11,
                            color=COLOR_TEXT_DIM,
                            weight=ft.FontWeight.BOLD,
                        ),
                    ],
                    spacing=4,
                ),
                ft.Divider(height=1, color=COLOR_BORDER),
                ft.ListView(
                    ref=log_list,
                    controls=[
                        ft.Text(
                            "[NetGuard] Ожидание запуска... "
                            "Выберите интерфейс и нажмите 'ВКЛЮЧИТЬ ЗАЩИТУ'",
                            color=COLOR_TEXT_DIM,
                            size=11,
                        )
                    ],
                    expand=True,
                    spacing=2,
                    auto_scroll=True,
                ),
            ],
            expand=True,
            spacing=6,
        ),
        padding=Padding(left=14, right=14, top=14, bottom=14),
        bgcolor=COLOR_PANEL,
        border=Border(
            top=BorderSide(1, COLOR_BORDER),
            right=BorderSide(1, COLOR_BORDER),
            bottom=BorderSide(1, COLOR_BORDER),
            left=BorderSide(1, COLOR_BORDER),
        ),
        border_radius=10,
        margin=Margin(left=24, right=24, top=10, bottom=16),
        expand=True,
    )

    # ── Итоговая компоновка с вкладками (Tabs) ─────────
    # Вкладка 1: Активная защита
    tab_protection_content = ft.Column(
        controls=[
            header,
            control_row,
            status_panel_widget,
            log_panel_widget,
        ],
        expand=True,
        spacing=0,
    )

    # Вкладка 2: Мониторинг сети
    tab_monitoring_content = ft.Container(
        content=ft.Text(
            "Здесь будет интерактивная таблица пользователей для ручного бана (Этап 3)",
            color=COLOR_TEXT_DIM,
            size=16,
            weight=ft.FontWeight.BOLD,
            text_align=ft.TextAlign.CENTER,
        ),
        alignment=ft.Alignment(0, 0),
        expand=True,
    )

    tabs = ft.Tabs(
        length=2,
        expand=True,
        content=ft.Column(
            expand=True,
            spacing=0,
            controls=[
                ft.TabBar(
                    tabs=[
                        ft.Tab(label="🛡️ Активная Защита"),
                        ft.Tab(label="👥 Мониторинг Сети (Устройства)"),
                    ],
                    label_color=COLOR_ACCENT,
                    unselected_label_color=COLOR_TEXT_DIM,
                    indicator_color=COLOR_ACCENT,
                ),
                ft.TabBarView(
                    expand=True,
                    controls=[
                        tab_protection_content,
                        tab_monitoring_content,
                    ]
                )
            ]
        )
    )

    page.add(tabs)

    # ──────────────────────────────────────────────────
    #  ДИАЛОГ "НЕТ ПРАВ АДМИНИСТРАТОРА"
    # ──────────────────────────────────────────────────
    if not is_admin:
        def close_admin_dialog(e):
            admin_dialog.open = False
            page.update()

        admin_dialog = ft.AlertDialog(
            modal=True,
            title=ft.Row(
                controls=[
                    ft.Icon(ft.Icons.ADMIN_PANEL_SETTINGS, color=COLOR_DANGER, size=28),
                    ft.Text(
                        "  Недостаточно прав!",
                        color=COLOR_DANGER,
                        size=18,
                        weight=ft.FontWeight.BOLD,
                    ),
                ]
            ),
            content=ft.Column(
                controls=[
                    ft.Text(
                        "Для перехвата сетевых пакетов и управления\n"
                        "Брандмауэром Windows требуются права\n"
                        "Администратора.",
                        color=COLOR_TEXT,
                        size=14,
                    ),
                    ft.Divider(height=12, color="transparent"),
                    ft.Container(
                        content=ft.Text(
                            "⚠  Запустите приложение от имени Администратора!",
                            color=COLOR_DANGER,
                            size=13,
                            weight=ft.FontWeight.BOLD,
                        ),
                        bgcolor=COLOR_DANGER_DIM,
                        padding=Padding(left=10, right=10, top=10, bottom=10),
                        border_radius=6,
                    ),
                ],
                tight=True,
                spacing=4,
            ),
            actions=[
                ft.TextButton(
                    "Понятно",
                    on_click=close_admin_dialog,
                    style=ft.ButtonStyle(color=COLOR_ACCENT),
                )
            ],
            actions_alignment=ft.MainAxisAlignment.END,
            bgcolor=COLOR_PANEL,
            shape=ft.RoundedRectangleBorder(radius=12),
        )

        page.overlay.append(admin_dialog)
        admin_dialog.open = True
        page.update()


# ──────────────────────────────────────────────────
#  ТОЧКА ВХОДА (Flet 0.80+: run() вместо app())
# ──────────────────────────────────────────────────
if __name__ == "__main__":
    ft.run(main)
