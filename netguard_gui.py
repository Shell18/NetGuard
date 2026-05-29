"""
NetGuard — ARP Spoof Detector & Active Defense System
GUI-приложение на базе Flet (Modern Dark Theme)

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
import flet as ft
from scapy.all import sniff, ARP, conf, Ether, srp1, sendp

# ──────────────────────────────────────────────────
#  ГЛОБАЛЬНОЕ СОСТОЯНИЕ ПРИЛОЖЕНИЯ
# ──────────────────────────────────────────────────
gateway_ip: str | None = None
gateway_mac: str | None = None
selected_iface_name: str | None = None
antidote_started: bool = False
sniff_thread: threading.Thread | None = None
is_protecting: bool = False

# ──────────────────────────────────────────────────
#  ВСПОМОГАТЕЛЬНЫЕ СЕТЕВЫЕ ФУНКЦИИ (ИЗ arp_sniffer.py)
# ──────────────────────────────────────────────────

def get_gateway_ip() -> str | None:
    """Определяет IP шлюза по умолчанию через таблицу маршрутизации Scapy."""
    try:
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
    Определяет MAC шлюза:
    1) Активный ARP-запрос через Scapy srp1
    2) Fallback — системный кэш ARP
    """
    try:
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_address)
        ans = srp1(pkt, iface=iface_name, timeout=2, verbose=False)
        if ans and ARP in ans:
            return ans[ARP].hwsrc.lower()
    except Exception:
        pass
    return get_mac_from_arp_cache(ip_address)


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
    Каждые 0.5 с отправляет широковещательный ARP-ответ,
    утверждающий легитимный MAC роутера.
    """
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=2,
        psrc=router_ip,
        hwsrc=real_router_mac,
        pdst="255.255.255.255"
    )
    while True:
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
    global antidote_started, sniff_thread, is_protecting

    # ── Настройки окна ──────────────────────────────
    page.title = "NetGuard — ARP Spoof Detector"
    page.theme_mode = ft.ThemeMode.DARK
    page.bgcolor = "#0A0E1A"
    page.window.width = 900
    page.window.height = 680
    page.window.min_width = 750
    page.window.min_height = 550
    page.padding = 0
    page.fonts = {
        "Roboto Mono": "https://fonts.gstatic.com/s/robotomono/v22/L0xuDF4xlVMF-BfR8bXMIhJHg45mwgGEFl0_3vq_ROW4.woff2"
    }

    # ── Проверка прав администратора ─────────────────
    is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())

    # ── Цветовая палитра (задана как константы) ──────
    COLOR_BG          = "#0A0E1A"
    COLOR_PANEL       = "#111827"
    COLOR_PANEL_BORDER = "#1E2D45"
    COLOR_ACCENT      = "#00D4FF"
    COLOR_ACCENT_DIM  = "#003D5C"
    COLOR_SUCCESS     = "#00E676"
    COLOR_DANGER      = "#FF1744"
    COLOR_DANGER_DIM  = "#4A0010"
    COLOR_TEXT_DIM    = "#607090"
    COLOR_TEXT        = "#C8D8F0"

    # ──────────────────────────────────────────────────
    #  СОСТОЯНИЕ UI (ref-объекты для обновления)
    # ──────────────────────────────────────────────────
    iface_dropdown    = ft.Ref[ft.Dropdown]()
    start_btn         = ft.Ref[ft.ElevatedButton]()
    status_text       = ft.Ref[ft.Text]()
    router_ip_text    = ft.Ref[ft.Text]()
    router_mac_text   = ft.Ref[ft.Text]()
    status_panel      = ft.Ref[ft.Container]()
    log_list          = ft.Ref[ft.ListView]()
    log_panel         = ft.Ref[ft.Container]()

    # ──────────────────────────────────────────────────
    #  ФУНКЦИЯ ДОБАВЛЕНИЯ СТРОКИ ЛОГА
    # ──────────────────────────────────────────────────
    def add_log(text: str, color: str = COLOR_TEXT, bold: bool = False):
        """
        Добавляет строку лога в ListView внизу экрана.

        КЛЮЧЕВОЙ МОМЕНТ ИНТЕГРАЦИИ Scapy → Flet:
        Scapy работает в отдельном потоке (sniff_thread).
        Чтобы безопасно обновить UI из стороннего потока,
        нужно вызвать page.update() ПОСЛЕ изменения controls.
        Flet требует, чтобы все изменения controls были видны
        через page.update() или явный вызов control.update().
        """
        timestamp = time.strftime("%H:%M:%S")
        entry = ft.Text(
            f"[{timestamp}]  {text}",
            color=color,
            size=11,
            weight=ft.FontWeight.BOLD if bold else ft.FontWeight.NORMAL,
            font_family="Roboto Mono",
            selectable=True,
        )
        # Добавляем строку в список и прокручиваем вниз
        log_list.current.controls.append(entry)
        # Ограничиваем количество строк, чтобы не перегружать память
        if len(log_list.current.controls) > 500:
            log_list.current.controls.pop(0)
        # Обновляем только ListView, а не всю страницу — это эффективнее
        log_list.current.update()

    # ──────────────────────────────────────────────────
    #  ФУНКЦИЯ АКТИВАЦИИ РЕЖИМА ТРЕВОГИ
    # ──────────────────────────────────────────────────
    def trigger_alert(attacker_mac: str, attacker_ip: str | None):
        """
        Визуальная и звуковая тревога при обнаружении атаки.
        Вызывается из потока sniff_thread → обновляет UI через page.update().
        """
        # 1. Красим фон панели статуса в ярко-красный
        status_panel.current.bgcolor = COLOR_DANGER_DIM
        status_panel.current.border = ft.border.all(2, COLOR_DANGER)

        # 2. Меняем текст статуса
        status_text.current.value = "⚠  ВНИМАНИЕ: ОБНАРУЖЕНА КИБЕРАТАКА!"
        status_text.current.color = COLOR_DANGER
        status_text.current.size = 20

        # 3. Обновляем страницу целиком — нужно для обновления нескольких контролов сразу
        page.update()

        # 4. Звуковой сигнал тревоги (частота 2000 Гц, длительность 1000 мс)
        # winsound.Beep блокирует поток, поэтому запускаем в отдельном мини-потоке
        threading.Thread(
            target=winsound.Beep, args=(2000, 1000), daemon=True
        ).start()

        # 5. Логи об атаке
        add_log("═" * 60, COLOR_DANGER, bold=True)
        add_log("ОБНАРУЖЕН ARP-SPOOFING РОУТЕРА!", COLOR_DANGER, bold=True)
        add_log(f"Шлюз (IP): {gateway_ip}", COLOR_DANGER)
        add_log(f"Эталонный MAC: {gateway_mac}", COLOR_DANGER)
        add_log(f"Атакующий MAC: {attacker_mac}", COLOR_DANGER)
        if attacker_ip:
            add_log(f"IP атакующего: {attacker_ip}", COLOR_DANGER)
            add_log(f"[+] Запущена функция БАНА для IP: {attacker_ip}", COLOR_DANGER, bold=True)
        add_log("═" * 60, COLOR_DANGER, bold=True)

    # ──────────────────────────────────────────────────
    #  CALLBACK-ФУНКЦИЯ ДЛЯ SCAPY SNIFF
    # ──────────────────────────────────────────────────
    def arp_callback(packet):
        """
        Вызывается Scapy для каждого перехваченного ARP-пакета.
        Работает в потоке sniff_thread.

        СВЯЗЬ С FLET:
        После формирования строки лога вызываем add_log(),
        которая добавляет ft.Text в ListView и вызывает
        log_list.current.update() для немедленного отображения
        без блокировки основного UI-потока.
        """
        global gateway_ip, gateway_mac, selected_iface_name, antidote_started

        try:
            if ARP not in packet:
                return

            arp = packet[ARP]
            op_code = arp.op
            src_ip  = arp.psrc
            src_mac = arp.hwsrc
            dst_ip  = arp.pdst

            if op_code == 1:
                # ARP Request
                add_log(
                    f"[ЗАПРОС]  Кто {dst_ip}? → спросил {src_ip} ({src_mac})",
                    COLOR_TEXT_DIM
                )
            elif op_code == 2:
                # ARP Reply
                add_log(
                    f"[ОТВЕТ]   {src_ip} → MAC: {src_mac}  (для {dst_ip})",
                    COLOR_TEXT
                )

                # ── ДЕТЕКТОР СПУФИНГА ─────────────────────────────
                if gateway_ip and src_ip == gateway_ip:
                    if src_mac.lower() != gateway_mac.lower():
                        # Найдена атака — получаем IP атакующего
                        attacker_ip = get_ip_from_arp_cache(src_mac)

                        # Блокируем в брандмауэре
                        if attacker_ip:
                            ban_attacker(attacker_ip)

                        # Активируем тревогу в интерфейсе
                        trigger_alert(src_mac, attacker_ip)

                        # Запускаем ARP-антидот (только один раз)
                        if not antidote_started:
                            antidote_started = True
                            add_log(
                                "[+] АКТИВИРОВАН ARP-АНТИДОТ: Подавление атаки в локальной сети...",
                                COLOR_SUCCESS, bold=True
                            )
                            threading.Thread(
                                target=antidote_worker,
                                args=(gateway_ip, gateway_mac, selected_iface_name),
                                daemon=True
                            ).start()
            else:
                add_log(
                    f"[ИНОЕ op={op_code}]  {src_ip} ({src_mac}) → {dst_ip}",
                    COLOR_TEXT_DIM
                )

        except Exception as e:
            add_log(f"[!] Ошибка парсинга пакета: {e}", COLOR_DANGER)

    # ──────────────────────────────────────────────────
    #  ЗАПУСК ЗАЩИТЫ (обработчик кнопки)
    # ──────────────────────────────────────────────────
    def on_start_protection(e):
        """
        Обработчик кнопки 'ВКЛЮЧИТЬ ЗАЩИТУ'.
        Запускает определение шлюза + MAC в отдельном потоке,
        затем стартует sniff() в ещё одном потоке.
        """
        global gateway_ip, gateway_mac, selected_iface_name
        global antidote_started, sniff_thread, is_protecting

        if is_protecting:
            return  # Уже активно — игнорируем повторный клик

        # Получаем выбранный интерфейс
        if not iface_dropdown.current.value:
            add_log("[!] Сначала выберите сетевой интерфейс!", COLOR_DANGER, bold=True)
            return

        # Блокируем кнопку и показываем процесс инициализации
        start_btn.current.disabled = True
        start_btn.current.text = "Инициализация..."
        start_btn.current.bgcolor = "#1A3A4A"
        page.update()

        def init_and_sniff():
            """Инициализация + запуск sniffer'а в фоновом потоке."""
            global gateway_ip, gateway_mac, selected_iface_name
            global antidote_started, sniff_thread, is_protecting

            selected_iface_name = iface_dropdown.current.value
            antidote_started = False

            # Шаг 1: определяем IP шлюза
            add_log("[*] Определение IP-адреса шлюза по умолчанию...", COLOR_ACCENT)
            gw_ip = get_gateway_ip()
            if not gw_ip:
                add_log("[!] Не удалось определить IP шлюза автоматически.", COLOR_DANGER, bold=True)
                # Сбрасываем кнопку
                start_btn.current.disabled = False
                start_btn.current.text = "ВКЛЮЧИТЬ ЗАЩИТУ"
                start_btn.current.bgcolor = COLOR_ACCENT_DIM
                page.update()
                return

            gateway_ip = gw_ip
            add_log(f"[+] Шлюз обнаружен: {gateway_ip}", COLOR_SUCCESS)

            # Шаг 2: определяем эталонный MAC шлюза
            add_log(f"[*] Получение эталонного MAC-адреса для {gateway_ip}...", COLOR_ACCENT)
            gw_mac = get_gateway_mac(gateway_ip, selected_iface_name)
            if not gw_mac:
                add_log("[!] Не удалось определить MAC шлюза.", COLOR_DANGER, bold=True)
                start_btn.current.disabled = False
                start_btn.current.text = "ВКЛЮЧИТЬ ЗАЩИТУ"
                start_btn.current.bgcolor = COLOR_ACCENT_DIM
                page.update()
                return

            gateway_mac = gw_mac

            # Обновляем информационную панель (данные о роутере)
            # ИНТЕГРАЦИЯ Scapy → Flet:
            # Из фонового потока устанавливаем .value у Text-элементов
            # и вызываем page.update() для применения изменений в UI.
            router_ip_text.current.value  = f"IP роутера:  {gateway_ip}"
            router_mac_text.current.value = f"MAC эталон: {gateway_mac}"
            status_text.current.value = "🛡  Сеть под защитой"
            status_text.current.color = COLOR_SUCCESS
            status_text.current.size  = 22
            status_panel.current.bgcolor = "#0A2A1A"
            status_panel.current.border  = ft.border.all(2, COLOR_SUCCESS)
            start_btn.current.text    = "● ЗАЩИТА АКТИВНА"
            start_btn.current.bgcolor = "#003D1A"
            start_btn.current.color   = COLOR_SUCCESS
            # После обновления нескольких элементов — один вызов page.update()
            page.update()

            add_log(f"[+] Эталонный MAC зафиксирован: {gateway_mac}", COLOR_SUCCESS, bold=True)
            add_log("─" * 60, COLOR_TEXT_DIM)
            add_log("[*] Запущен активный мониторинг ARP-трафика...", COLOR_ACCENT, bold=True)
            add_log("[*] Нажмите ✖ для завершения.", COLOR_TEXT_DIM)
            add_log("─" * 60, COLOR_TEXT_DIM)

            is_protecting = True

            # Шаг 3: запускаем sniff() — блокирует поток до остановки
            try:
                sniff(
                    iface=selected_iface_name,
                    filter="arp",
                    prn=arp_callback,
                    store=0,
                    count=0
                )
            except Exception as ex:
                add_log(f"[!] Ошибка Scapy sniff: {ex}", COLOR_DANGER, bold=True)

        # Запускаем инициализацию + sniff в отдельном daemon-потоке
        sniff_thread = threading.Thread(target=init_and_sniff, daemon=True)
        sniff_thread.start()

    # ──────────────────────────────────────────────────
    #  ОБРАБОТЧИК ЗАКРЫТИЯ ОКНА
    # ──────────────────────────────────────────────────
    def on_window_close(e):
        """
        Вызывается при закрытии окна.
        Удаляет правило брандмауэра, чтобы не засорять систему.
        """
        cleanup_firewall_rule()
        page.window.destroy()

    page.window.on_close = on_window_close

    # ──────────────────────────────────────────────────
    #  ФОРМИРУЕМ СПИСОК ИНТЕРФЕЙСОВ ДЛЯ DROPDOWN
    # ──────────────────────────────────────────────────
    ifaces_list = list(conf.ifaces.values())
    dropdown_options = []
    for iface in ifaces_list:
        label = f"{iface.description}  [{iface.ip or 'нет IP'}]"
        dropdown_options.append(ft.dropdown.Option(key=iface.name, text=label))

    # ──────────────────────────────────────────────────
    #  ПОСТРОЕНИЕ ИНТЕРФЕЙСА
    # ──────────────────────────────────────────────────

    # ── Заголовок ────────────────────────────────────
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
                            font_family="Roboto Mono",
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
        padding=ft.padding.symmetric(horizontal=24, vertical=16),
        bgcolor=COLOR_PANEL,
        border=ft.border.only(bottom=ft.BorderSide(1, COLOR_PANEL_BORDER)),
    )

    # ── Панель выбора интерфейса + кнопка запуска ────
    control_row = ft.Container(
        content=ft.Row(
            controls=[
                ft.Dropdown(
                    ref=iface_dropdown,
                    label="Сетевой интерфейс",
                    hint_text="Выберите интерфейс для мониторинга...",
                    options=dropdown_options,
                    expand=True,
                    bgcolor=COLOR_PANEL,
                    color=COLOR_TEXT,
                    border_color=COLOR_PANEL_BORDER,
                    focused_border_color=COLOR_ACCENT,
                    label_style=ft.TextStyle(color=COLOR_TEXT_DIM),
                ),
                ft.ElevatedButton(
                    ref=start_btn,
                    text="ВКЛЮЧИТЬ ЗАЩИТУ",
                    icon=ft.Icons.SHIELD,
                    on_click=on_start_protection,
                    bgcolor=COLOR_ACCENT_DIM,
                    color=COLOR_ACCENT,
                    height=52,
                    style=ft.ButtonStyle(
                        shape=ft.RoundedRectangleBorder(radius=8),
                        padding=ft.padding.symmetric(horizontal=24, vertical=14),
                        text_style=ft.TextStyle(
                            size=14,
                            weight=ft.FontWeight.BOLD,
                            font_family="Roboto Mono",
                        ),
                        overlay_color={"hovered": "#004A6A"},
                    ),
                ),
            ],
            spacing=16,
        ),
        padding=ft.padding.symmetric(horizontal=24, vertical=14),
        bgcolor=COLOR_PANEL,
        border=ft.border.only(bottom=ft.BorderSide(1, COLOR_PANEL_BORDER)),
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
                    font_family="Roboto Mono",
                ),
                ft.Divider(height=8, color="transparent"),
                ft.Row(
                    controls=[
                        ft.Icon(ft.Icons.ROUTER, color=COLOR_TEXT_DIM, size=16),
                        ft.Text(
                            ref=router_ip_text,
                            value="IP роутера:  —",
                            size=13,
                            color=COLOR_TEXT_DIM,
                            font_family="Roboto Mono",
                        ),
                    ],
                    spacing=8,
                ),
                ft.Row(
                    controls=[
                        ft.Icon(ft.Icons.FINGERPRINT, color=COLOR_TEXT_DIM, size=16),
                        ft.Text(
                            ref=router_mac_text,
                            value="MAC эталон: —",
                            size=13,
                            color=COLOR_TEXT_DIM,
                            font_family="Roboto Mono",
                        ),
                    ],
                    spacing=8,
                ),
            ],
            spacing=4,
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
        ),
        padding=ft.padding.symmetric(horizontal=32, vertical=20),
        bgcolor=COLOR_PANEL,
        border=ft.border.all(2, COLOR_PANEL_BORDER),
        border_radius=12,
        margin=ft.margin.symmetric(horizontal=24, vertical=10),
        animate=ft.animation.Animation(400, ft.AnimationCurve.EASE_IN_OUT),
    )

    # ── Лог-панель (нижняя часть) ─────────────────────
    log_panel_widget = ft.Container(
        ref=log_panel,
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
                ft.Divider(height=1, color=COLOR_PANEL_BORDER),
                ft.ListView(
                    ref=log_list,
                    controls=[
                        ft.Text(
                            "[NetGuard] Ожидание запуска... Выберите интерфейс и нажмите 'ВКЛЮЧИТЬ ЗАЩИТУ'",
                            color=COLOR_TEXT_DIM,
                            size=11,
                            font_family="Roboto Mono",
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
        padding=ft.padding.all(14),
        bgcolor=COLOR_PANEL,
        border=ft.border.all(1, COLOR_PANEL_BORDER),
        border_radius=10,
        margin=ft.margin.only(left=24, right=24, bottom=16),
        expand=True,
    )

    # ── Итоговая компоновка страницы ─────────────────
    page.add(
        ft.Column(
            controls=[
                header,
                control_row,
                status_panel_widget,
                log_panel_widget,
            ],
            expand=True,
            spacing=0,
        )
    )

    # ──────────────────────────────────────────────────
    #  ПОКАЗ ДИАЛОГА ЕСЛИ НЕТ ПРАВ АДМИНИСТРАТОРА
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
                            font_family="Roboto Mono",
                        ),
                        bgcolor=COLOR_DANGER_DIM,
                        padding=ft.padding.all(10),
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
#  ТОЧКА ВХОДА
# ──────────────────────────────────────────────────
if __name__ == "__main__":
    ft.app(target=main)
