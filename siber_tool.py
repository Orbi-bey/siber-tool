#!/usr/bin/env python3

import os
import socket
import requests
import hashlib
import time
import subprocess
from colorama import Fore, Style, init
from pyfiglet import figlet_format
from scapy.all import ARP, sniff

init(autoreset=True)

def check_root():
    if os.geteuid() != 0:
        print(Fore.RED + "Bu aracı çalıştırmak için root yetkisi gereklidir. Lütfen 'sudo' ile başlatın.")
        exit()

def ascii_header(text, color=Fore.GREEN):
    print(color + figlet_format(text, font="slant"))

def loading_animation():
    print(Fore.YELLOW + "Loading by.orbi...")
    for _ in range(3):
        time.sleep(0.5)
        print(Fore.CYAN + ".", end="", flush=True)
    print()

def port_scan():
    ascii_header("Port Scanner", Fore.CYAN)
    target = input("Hedef IP veya domain: ")
    for port in range(1, 1025):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(0.5)
        result = s.connect_ex((target, port))
        if result == 0:
            print(Fore.GREEN + f"[+] Açık Port: {port}")
        s.close()

def network_traffic_analysis():
    ascii_header("Traffic Sniff", Fore.MAGENTA)
    print("Ağ trafiği dinleniyor (ilk 10 paket)...")
    packets = sniff(count=10)
    packets.summary()

def ip_lookup():
    ascii_header("IP Lookup", Fore.GREEN)
    ip = input("IP veya domain girin: ")
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}")
        print(r.json())
    except:
        print(Fore.RED + "Bağlantı hatası!")

def password_strength_test():
    ascii_header("Password Test", Fore.RED)
    pw = input("Parola: ")
    score = len(pw) + sum(c.isdigit() for c in pw)
    strength = "Zayıf" if score < 8 else "Orta" if score < 12 else "Güçlü"
    print(Fore.YELLOW + f"Parola gücü: {strength}")

def file_hash_check():
    ascii_header("Hash Checker", Fore.YELLOW)
    path = input("Dosya yolu: ")
    try:
        with open(path, "rb") as f:
            h = hashlib.sha256(f.read()).hexdigest()
            print(Fore.GREEN + f"SHA-256: {h}")
    except:
        print(Fore.RED + "Dosya okunamadı!")

def arp_poison_detect():
    ascii_header("ARP Monitor", Fore.LIGHTYELLOW_EX)
    print("ARP paketleri dinleniyor...")

    def callback(pkt):
        if ARP in pkt and pkt[ARP].op == 2:
            print(Fore.RED + f"[!] ARP Spoof tespiti: {pkt[ARP].psrc} -> {pkt[ARP].hwsrc}")

    sniff(filter="arp", prn=callback, store=0)

def system_vulnerability_scan():
    ascii_header("Vuln Scan", Fore.LIGHTGREEN_EX)
    os.system("nmap -sV --script=vuln")

def internal_network_mapping():
    ascii_header("Network Map", Fore.LIGHTMAGENTA_EX)
    os.system("nmap -sn 192.168.1.0/24")

def dark_web_monitoring():
    ascii_header("Dark Web", Fore.LIGHTCYAN_EX)
    target = input("Dark Web adresi (örnek: abcxyz.onion): ")
    session = get_tor_session()
    try:
        response = session.get(f"http://{target}")
        print(Fore.GREEN + response.text[:500])
    except Exception as e:
        print(Fore.RED + f"Hata: {e}")

def packet_sniffer():
    ascii_header("Sniffer", Fore.LIGHTRED_EX)
    print("Paketler yakalanıyor (ilk 5)...")
    pkts = sniff(count=5)
    pkts.summary()

def network_scanner():
    ascii_header("Net Scanner", Fore.LIGHTGREEN_EX)
    target = input("Hedef ağ (örnek: 192.168.1.0/24): ")
    os.system(f"nmap -sP {target}")

def get_tor_session():
    session = requests.Session()
    session.proxies = {
        'http': 'socks5h://127.0.0.1:9050',
        'https': 'socks5h://127.0.0.1:9050',
    }
    return session

def menu():
    ascii_header("Siber Güvenlik Araçları", Fore.LIGHTCYAN_EX)
    print(Fore.LIGHTBLUE_EX + """
╭──────────────────────────────────────────────────────────────────────────────╮
┃                          1. Port Scanner                                     ┃
┃                          2. Trafik Dinleme                                   ┃
┃                          3. IP Lookup                                        ┃
┃                          4. Parola Testi                                    ┃
┃                          5. Hash Checker                                    ┃
┃                          6. ARP Spoofing Tespiti                            ┃
┃                          7. Sistem Açığı Tarama                            ┃
┃                          8. Network Mapping                                 ┃
┃                          9. Dark Web İzleme                                 ┃
┃                         10. Paket Yakalama                                  ┃
┃                         11. Ağ Tarama                                       ┃
╰──────────────────────────────────────────────────────────────────────────────╯

╭──────────────────────────────────────────────────────────────────────────────╮
┃Instagram: @j.tay_ler             Github: https://github.com/orbi-bey ┃
╰──────────────────────────────────────────────────────────────────────────────╯
""")

def main():
    check_root()
    loading_animation()
    tools = [
        port_scan, network_traffic_analysis, ip_lookup, password_strength_test,
        file_hash_check, arp_poison_detect, system_vulnerability_scan,
        internal_network_mapping, dark_web_monitoring, packet_sniffer, network_scanner
    ]

    while True:
        menu()
        choice = input(Fore.CYAN + "Seçim yapın: ")
        if choice == "q":
            print(Fore.RED + "Güle güle!")
            break
        try:
            index = int(choice) - 1
            if 0 <= index < len(tools):
                tools[index]()
            else:
                print(Fore.RED + "Geçersiz seçim.")
        except ValueError:
            print(Fore.RED + "Sayı girilmedi!")

if __name__ == "__main__":
    main()

