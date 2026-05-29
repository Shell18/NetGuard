import sys
import subprocess
import re
import threading
import time
from scapy.all import sniff, ARP, conf, Ether, srp1, sendp

# Глобальные переменные эталона (White Reference)
gateway_ip = None
gateway_mac = None
selected_iface_name = None
antidote_started = False

def get_gateway_ip():
    """
    Автоматически определяет IP-адрес шлюза (роутера) по умолчанию
    через таблицу маршрутизации Scapy.
    """
    try:
        # conf.route.route("0.0.0.0") возвращает (интерфейс, IP_выхода, IP_шлюза)
        _, _, gw_ip = conf.route.route("0.0.0.0")
        if gw_ip and gw_ip != "0.0.0.0":
            return gw_ip
    except Exception as e:
        print(f"[-] Не удалось автоматически определить IP шлюза: {e}")
    return None

def get_mac_from_arp_cache(ip_address):
    """
    Ищет MAC-адрес указанного IP-адреса в системном кэше ARP (команда arp -a).
    Используется как надежный fallback.
    """
    try:
        # Запускаем системную команду arp -a
        output = subprocess.check_output(["arp", "-a"], stderr=subprocess.DEVNULL)
        # Декодируем вывод с учетом кодировки cp866 (стандартная для Windows cmd)
        decoded_output = output.decode("cp866", errors="ignore")
        
        for line in decoded_output.splitlines():
            if ip_address in line:
                # Ищем MAC-адрес (формат xx-xx-xx-xx-xx-xx или xx:xx:xx:xx:xx:xx)
                mac_match = re.search(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", line)
                if mac_match:
                    return mac_match.group(0).replace("-", ":").lower()
    except Exception as e:
        print(f"[!] Ошибка чтения системной таблицы ARP: {e}")
    return None

def get_gateway_mac(ip_address, iface_name):
    """
    Определяет честный MAC-адрес шлюза.
    Сначала отправляет активный ARP-запрос через Scapy srp1.
    Если не удается (таймаут или отсутствие прав), пробует прочитать системный ARP-кэш.
    Если оба способа не сработали, просит пользователя ввести вручную.
    """
    print(f"[*] Шаг 1: Отправка активного ARP-запроса на {ip_address} через интерфейс {iface_name}...")
    
    try:
        # Создаем ARP-запрос: L2 Ether-фрейм на широковещательный адрес ff:ff:ff:ff:ff:ff
        # оборачивает L3 ARP-запрос к нужному IP
        arp_pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_address)
        # Отправляем и ждем один ответ
        ans = srp1(arp_pkt, iface=iface_name, timeout=2, verbose=False)
        if ans and ARP in ans:
            mac = ans[ARP].hwsrc.lower()
            print(f"[+] Успешно получен MAC-адрес шлюза: {mac} (через ARP-запрос)")
            return mac
    except Exception as e:
        print(f"[-] Активный ARP-запрос завершился ошибкой (возможно, нет прав администратора): {e}")
        
    print(f"[*] Шаг 2: Попытка получить MAC-адрес из системного ARP-кэша...")
    cached_mac = get_mac_from_arp_cache(ip_address)
    if cached_mac:
        print(f"[+] Найден MAC-адрес в системном кэше: {cached_mac}")
        return cached_mac
        
    print(f"\n[!] Не удалось автоматически определить MAC-адрес для IP {ip_address}.")
    while True:
        try:
            manual_mac = input(f"Пожалуйста, введите реальный MAC-адрес шлюза вручную (например, b0:95:75:87:bb:ef):\n> ").strip().lower()
            # Простая валидация MAC-адреса
            if re.match(r"^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$", manual_mac):
                normalized = manual_mac.replace("-", ":")
                print(f"[+] Принят эталонный MAC-адрес (введен вручную): {normalized}")
                return normalized
            else:
                print("[-] Неверный формат MAC-адреса. Пример правильного формата: b0:95:75:87:bb:ef")
        except KeyboardInterrupt:
            print("\n[!] Отменено пользователем.")
            sys.exit(0)

def get_ip_from_arp_cache(mac_address):
    """
    Ищет IP-адрес по заданному MAC-адресу в системном кэше ARP.
    """
    try:
        # Приводим MAC к единому виду для сравнения (Windows arp -a использует дефисы)
        mac_normalized = mac_address.lower().replace(":", "-")
        output = subprocess.check_output(["arp", "-a"], stderr=subprocess.DEVNULL)
        decoded_output = output.decode("cp866", errors="ignore")
        
        for line in decoded_output.splitlines():
            if mac_normalized in line.lower():
                # Регулярка для извлечения IP-адреса (первое совпадение в строке)
                ip_match = re.search(r"((?:[0-9]{1,3}\.){3}[0-9]{1,3})", line)
                if ip_match:
                    return ip_match.group(1)
    except Exception as e:
        print(f"[!] Ошибка при поиске IP по MAC в кэше: {e}")
    return None

def ban_attacker(attacker_ip):
    """
    Локально блокирует IP-адрес атакующего через Брандмауэр Windows.
    """
    print(f"[+] Запущена функция БАНА для IP: {attacker_ip}")
    try:
        # Добавляем правило блокировки в брандмауэр Windows
        cmd = f'netsh advfirewall firewall add rule name="BLOCK_ARP_ATTACKER" dir=in action=block remoteip={attacker_ip}'
        subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"[+] IP {attacker_ip} успешно заблокирован в Брандмауэре Windows.")
    except Exception as e:
        print(f"[-] Не удалось заблокировать IP {attacker_ip} через Брандмауэр: {e}")

def antidote_worker(router_ip, real_router_mac, iface_name):
    """
    Фоновый поток антидота. Каждые 0.5 секунд рассылает легитимные ARP-ответы.
    """
    print("[+] АКТИВИРОВАН ARP-АНТИДОТ: Подавление атаки в локальной сети...")
    
    # Собираем легитимный ARP-ответ
    # Ether dst = широковещательный
    # ARP psrc = IP шлюза, hwsrc = реальный MAC шлюза, pdst = широковещательный
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

def start_antidote(router_ip, real_router_mac):
    """
    Запускает фоновый поток для отправки легитимных ARP-ответов.
    """
    global antidote_started, selected_iface_name
    if not antidote_started:
        antidote_started = True
        t = threading.Thread(
            target=antidote_worker,
            args=(router_ip, real_router_mac, selected_iface_name),
            daemon=True
        )
        t.start()

def show_interfaces():
    """
    Получает список всех сетевых интерфейсов через conf.ifaces,
    выводит их в консоль и возвращает список интерфейсов.
    """
    print("=== Список доступных сетевых интерфейсов ===")
    
    # conf.ifaces содержит список всех сетевых интерфейсов, обнаруженных Scapy.
    # Мы преобразуем его в список (list) для удобного выбора по индексу.
    ifaces_list = list(conf.ifaces.values())
    
    if not ifaces_list:
        print("Сетевые интерфейсы не найдены.")
        print("[!] Убедитесь, что в системе установлен драйвер Npcap/WinPcap.")
        sys.exit(1)
        
    for index, iface in enumerate(ifaces_list):
        # Извлекаем основные характеристики интерфейса:
        name = iface.name                 # Имя интерфейса в системе (в Windows это обычно GUID, например, \Device\NPF_{...})
        description = iface.description   # Понятное описание (например, "Intel(R) Wireless-AC 9560" или "Realtek PCIe GbE Family Controller")
        ip = iface.ip if iface.ip else "Нет IP"  # IP-адрес, привязанный к интерфейсу
        mac = iface.mac if iface.mac else "Нет MAC"  # Физический (MAC) адрес интерфейса
        
        print(f"[{index}] Имя: {name}")
        print(f"    Описание: {description}")
        print(f"    IP-адрес: {ip} | MAC-адрес: {mac}")
        print("-" * 50)
        
    return ifaces_list

def select_interface(ifaces_list):
    """
    Запрашивает у пользователя выбор интерфейса по его индексу в списке.
    """
    while True:
        try:
            choice = input("\nВведите номер сетевого интерфейса для сниффинга (например, 0): ").strip()
            idx = int(choice)
            if 0 <= idx < len(ifaces_list):
                selected = ifaces_list[idx]
                print(f"\n[+] Выбран интерфейс: {selected.description}")
                print(f"    Системное имя (Scapy): {selected.name}")
                return selected
            else:
                print(f"[-] Неверный номер. Пожалуйста, введите число от 0 до {len(ifaces_list) - 1}.")
        except ValueError:
            print("[-] Ошибка ввода. Пожалуйста, введите целое число.")
        except KeyboardInterrupt:
            print("\n[!] Отменено пользователем.")
            sys.exit(0)

def arp_callback(packet):
    """
    Функция-колбэк, вызываемая Scapy для каждого перехваченного пакета.
    Разбирает структуру ARP-пакета и выполняет детекцию ARP-spoofing'а.
    Обернута в try-except для устойчивости к ошибкам.
    """
    global gateway_ip, gateway_mac, selected_iface_name
    try:
        # Проверяем, содержит ли перехваченный пакет слой ARP.
        if ARP in packet:
            arp_layer = packet[ARP]
            op_code = arp_layer.op
            src_ip = arp_layer.psrc
            src_mac = arp_layer.hwsrc
            dst_ip = arp_layer.pdst
            
            # Форматируем вывод в зависимости от типа операции (Request / Reply)
            if op_code == 1:
                # Запрос (Request)
                print(f"[ARP ЗАПРОС] Кто владеет {dst_ip}? Спросил {src_ip} ({src_mac})")
            elif op_code == 2:
                # Ответ (Reply)
                print(f"[ARP ОТВЕТ]  У {src_ip} MAC-адрес {src_mac} (Отправлено для {dst_ip})")
                
                # Анализируем ответ от IP нашего роутера
                if gateway_ip and src_ip == gateway_ip:
                    # Сравниваем MAC-адреса, приводя к нижнему регистру
                    if src_mac.lower() != gateway_mac.lower():
                        # Выводим яркий красный варнинг в консоль
                        print("\n" + "=" * 80)
                        # \033[91m включает красный цвет, \033[0m сбрасывает цвета
                        print(f"\033[91m[!] КРИТИЧЕСКАЯ АТАКА: ОБНАРУЖЕН ARP-SPOOFING РОУТЕРА!\033[0m")
                        print(f"\033[91m    Шлюз (IP): {gateway_ip}\033[0m")
                        print(f"\033[91m    Ожидаемый MAC (эталон):  {gateway_mac}\033[0m")
                        print(f"\033[91m    Атакующий MAC (текущий): {src_mac}\033[0m")
                        print("=" * 80 + "\n")
                        
                        # 1. Попытка заблокировать IP атакующего
                        attacker_ip = get_ip_from_arp_cache(src_mac)
                        if attacker_ip:
                            ban_attacker(attacker_ip)
                        else:
                            print(f"[-] Не удалось определить IP-адрес атакующего по MAC {src_mac} (возможно, это вымышленный адрес/тест).")
                        
                        # 2. Запуск ARP-Антидота
                        start_antidote(gateway_ip, gateway_mac)
            else:
                # Другие редкие типы
                print(f"[ARP ДРУГОЕ (op={op_code})] {src_ip} ({src_mac}) -> {dst_ip}")
    except Exception as e:
        # Безопасный перехват любых исключений при обработке пакета
        print(f"[!] Ошибка при парсинге пакета: {e}")

def main():
    global gateway_ip, gateway_mac, selected_iface_name
    
    print("=" * 60)
    print("      ARP детектор спуфинга на Scapy (для ОС Windows)")
    print("=" * 60)
    
    try:
        # 1. Получаем список интерфейсов и даем пользователю выбрать нужный
        ifaces = show_interfaces()
        selected_iface = select_interface(ifaces)
        selected_iface_name = selected_iface.name
        
        # 2. Детектируем шлюз по умолчанию
        print("\n[*] Определение IP-адреса шлюза по умолчанию...")
        detected_ip = get_gateway_ip()
        if detected_ip:
            print(f"[+] Обнаружен IP-адрес шлюза: {detected_ip}")
            gateway_ip = detected_ip
        else:
            # Ручной ввод IP-адреса шлюза, если автоматический метод не сработал
            while True:
                ip_input = input("Пожалуйста, введите IP-адрес шлюза вручную (например, 192.168.0.1):\n> ").strip()
                # Простая регулярка для валидации IPv4
                if re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", ip_input):
                    gateway_ip = ip_input
                    break
                else:
                    print("[-] Неверный формат IP-адреса.")

        # 3. Разрешаем MAC-адрес шлюза для создания "Белого эталона"
        print(f"\n[*] Определение эталонного MAC-адреса для шлюза {gateway_ip}...")
        gateway_mac = get_gateway_mac(gateway_ip, selected_iface.name)
        
        print("\n" + "=" * 60)
        print("                БЕЛЫЙ ЭТАЛОН (УСТАНОВЛЕН)")
        print(f"   IP Роутера:  {gateway_ip}")
        print(f"   MAC Роутера: {gateway_mac}")
        print("=" * 60)
        
        print(f"\n[*] Запуск активного мониторинга ARP-трафика...")
        print(f"[*] Интерфейс: {selected_iface.description}")
        print("[*] Фильтр: только ARP-пакеты (filter=\"arp\")")
        print("[*] Нажмите Ctrl+C для остановки программы.\n")
        print("-" * 60)
        
        # 4. Запускаем бесконечный sniff()
        # count=0 означает бесконечный захват
        sniff(iface=selected_iface.name, filter="arp", prn=arp_callback, store=0, count=0)
        
    except PermissionError:
        print("\n[-] Ошибка прав доступа!")
        print("[!] Для работы с сырыми сокетами и сетевой картой в Windows требуются права Администратора.")
        print("[!] Запустите командную строку (cmd) или PowerShell от имени Администратора.")
    except KeyboardInterrupt:
        print("\n[!] Программа остановлена пользователем.")
    except Exception as e:
        print(f"\n[-] Произошла непредвиденная ошибка: {e}")
        print("[!] Проверьте, установлен ли Npcap (https://npcap.com/) на вашем компьютере.")
        print("[!] Без Npcap библиотека Scapy на Windows не может осуществлять захват сырых пакетов.")

if __name__ == "__main__":
    main()
