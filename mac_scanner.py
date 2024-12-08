import tkinter as tk
from tkinter import ttk, messagebox
import ttkbootstrap as ttk
from scapy.all import ARP, Ether, srp, getmacbyip
import psutil
import netifaces
import threading
import time
from datetime import datetime
import requests
import socket
import re
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP
import nmap
from collections import defaultdict
from tkinter import StringVar

class MACScanner:
    def __init__(self):
        self.is_scanning = False
        
        self.root = ttk.Window(themename="darkly")
        self.root.title("MAC Scanner")
        self.root.geometry("1200x800")
        
        # Asosiy container
        self.main_container = ttk.Frame(self.root)
        self.main_container.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Avval available_macs ni olish
        self.available_macs = self.get_available_macs()
        
        # MAC kiritish qismini yangilash
        self.search_frame = ttk.LabelFrame(self.main_container, text="MAC manzil qidirish")
        self.search_frame.pack(fill=tk.X, padx=5, pady=5)
        
        # MAC tanlash kombobox
        self.mac_var = StringVar()
        self.mac_combo = ttk.Combobox(
            self.search_frame,
            textvariable=self.mac_var,
            values=self.available_macs,
            width=30
        )
        self.mac_combo.pack(side=tk.LEFT, padx=5, pady=5)
        
        # MAC formatlash
        self.mac_combo.bind('<KeyRelease>', self.format_mac)
        self.mac_combo.bind('<<ComboboxSelected>>', self.on_mac_selected)
        
        # MAC manzil formati haqida yordam
        self.help_label = ttk.Label(
            self.search_frame,
            text="Format: XX:XX:XX:XX:XX:XX yoki avtomatik tanlang",
            font=('Arial', 9),
            foreground='gray'
        )
        self.help_label.pack(side=tk.LEFT, padx=5, pady=5)
        
        # Qidirish tugmasi
        self.search_btn = ttk.Button(
            self.search_frame,
            text="Qidirish",
            command=self.start_search,
            style='primary.TButton'
        )
        self.search_btn.pack(side=tk.LEFT, padx=5, pady=5)
        
        # Yangilash tugmasi
        self.refresh_btn = ttk.Button(
            self.search_frame,
            text="⟳ Yangilash",
            command=self.refresh_macs,
            style='info.TButton',
            width=10
        )
        self.refresh_btn.pack(side=tk.LEFT, padx=5, pady=5)
        
        # Tarmoqni skanerlash tugmasi
        self.scan_btn = ttk.Button(
            self.search_frame,
            text="Tarmoqni Skanerlash",
            command=self.start_network_scan,
            style='info.TButton'
        )
        self.scan_btn.pack(side=tk.LEFT, padx=5, pady=5)
        
        # Ma'lumotlar paneli
        self.notebook = ttk.Notebook(self.main_container)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Qurilma ma'lumotlari
        self.device_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.device_frame, text="Qurilma Ma'lumotlari")
        
        # Ma'lumotlar jadvali
        columns = ('parametr', 'qiymat')
        self.tree = ttk.Treeview(self.device_frame, columns=columns, show='headings')
        
        self.tree.heading('parametr', text='Parametr')
        self.tree.heading('qiymat', text='Qiymat')
        
        self.tree.column('parametr', width=200)
        self.tree.column('qiymat', width=400)
        
        self.tree.pack(fill=tk.BOTH, expand=True)
        
        # Tarmoq qurilmalari ro'yxati
        self.network_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.network_frame, text="Tarmoq Qurilmalari")
        
        columns = ('ip', 'mac', 'vendor', 'hostname', 'ports')
        self.network_tree = ttk.Treeview(self.network_frame, columns=columns, show='headings')
        
        self.network_tree.heading('ip', text='IP Manzil')
        self.network_tree.heading('mac', text='MAC Manzil')
        self.network_tree.heading('vendor', text='Ishlab Chiqaruvchi')
        self.network_tree.heading('hostname', text='Qurilma Nomi')
        self.network_tree.heading('ports', text='Ochiq Portlar')
        
        self.network_tree.pack(fill=tk.BOTH, expand=True)
        
        # Port ma'lumotlari uchun yangi tab
        self.port_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.port_frame, text="Port Ma'lumotlari")
        
        # Port ma'lumotlari jadvali
        port_columns = ('port', 'service', 'ip', 'device', 'status')
        self.port_tree = ttk.Treeview(self.port_frame, columns=port_columns, show='headings')
        
        self.port_tree.heading('port', text='Port')
        self.port_tree.heading('service', text='Xizmat Turi')
        self.port_tree.heading('ip', text='Ulangan IP')
        self.port_tree.heading('device', text='Ulangan Qurilma')
        self.port_tree.heading('status', text='Holati')
        
        self.port_tree.pack(fill=tk.BOTH, expand=True)
        
        # Port ma'lumotlari uchun Nmap scanner
        try:
            self.nm = nmap.PortScanner()
        except:
            self.nm = None
    
    def get_vendor_by_mac(self, mac):
        try:
            # MAC manzil formati: XX:XX:XX:XX:XX:XX
            mac = mac.replace(':', '').upper()[:6]
            url = f"https://api.macvendors.com/{mac}"
            response = requests.get(url)
            if response.status_code == 200:
                return response.text
            return "Noma'lum"
        except:
            return "Noma'lum"
    
    def get_open_ports(self, ip):
        open_ports = []
        common_ports = [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 8080]
        
        for port in common_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            result = sock.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        return open_ports
    
    def is_valid_mac(self, mac):
        pattern = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
        return bool(pattern.match(mac))
    
    def get_port_services(self, ip):
        """Port va ulangan qurilmalar ma'lumotlarini olish"""
        port_info = defaultdict(dict)
        common_services = {
            20: 'FTP-Data',
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            3306: 'MySQL',
            3389: 'RDP',
            8080: 'HTTP-Proxy'
        }
        
        try:
            if self.nm:
                # Nmap orqali chuqur skanerlash
                self.nm.scan(ip, arguments='-sS -sV -p-')
                
                if ip in self.nm.all_hosts():
                    for proto in self.nm[ip].all_protocols():
                        ports = self.nm[ip][proto].keys()
                        for port in ports:
                            service = self.nm[ip][proto][port]
                            port_info[port] = {
                                'service': service.get('name', 'Noma\'lum'),
                                'version': service.get('version', ''),
                                'state': service.get('state', 'Noma\'lum')
                            }
            
            # TCP connection test
            for port in common_services.keys():
                if port not in port_info:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    result = sock.connect_ex((ip, port))
                    if result == 0:
                        # Ulangan qurilma ma'lumotlarini olishga harakat
                        try:
                            remote_ip = sock.getpeername()[0]
                            try:
                                remote_host = socket.gethostbyaddr(remote_ip)[0]
                            except:
                                remote_host = "Noma'lum"
                            
                            port_info[port] = {
                                'service': common_services.get(port, 'Noma\'lum'),
                                'remote_ip': remote_ip,
                                'remote_host': remote_host,
                                'state': 'Ochiq'
                            }
                        except:
                            port_info[port] = {
                                'service': common_services.get(port, 'Noma\'lum'),
                                'state': 'Ochiq'
                            }
                    sock.close()
            
            return port_info
        except Exception as e:
            print(f"Port skanerlashda xatolik: {e}")
            return port_info
    
    def search_device(self):
        self.tree.delete(*self.tree.get_children())
        mac = self.mac_var.get()
        
        if not self.is_valid_mac(mac):
            messagebox.showerror("Xato", "Noto'g'ri MAC manzil formati")
            return
        
        try:
            # Asosiy ma'lumotlarni qo'shamiz
            vendor = self.get_vendor_by_mac(mac)
            self.tree.insert('', 'end', values=('MAC Manzil', mac))
            self.tree.insert('', 'end', values=('Ishlab Chiqaruvchi', vendor))
            
            # Tarmoqdagi qurilmani topish
            arp = ARP(pdst="192.168.1.0/24")
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            result = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.0/24"), timeout=3, verbose=0)[0]
            
            device_found = False
            for sent, received in result:
                if received.hwsrc.lower() == mac.lower():
                    device_found = True
                    ip = received.psrc
                    
                    # IP manzil
                    self.tree.insert('', 'end', values=('IP Manzil', ip))
                    
                    # Hostname
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                        self.tree.insert('', 'end', values=('Qurilma Nomi', hostname))
                    except:
                        self.tree.insert('', 'end', values=('Qurilma Nomi', "Noma'lum"))
                    
                    # Ochiq portlar
                    open_ports = self.get_open_ports(ip)
                    self.tree.insert('', 'end', values=('Ochiq Portlar', ', '.join(map(str, open_ports))))
                    
                    # Tarmoq tezligi
                    speed = psutil.net_if_stats().get(next(iter(psutil.net_if_stats())), None)
                    speed_str = f"{speed.speed}Mbps" if speed else "Noma'lum"
                    self.tree.insert('', 'end', values=('Tarmoq Tezligi', speed_str))
                    
                    # Port ma'lumotlarini olish
                    port_info = self.get_port_services(ip)
                    
                    # Port ma'lumotlarini jadvalga qo'shish
                    for port, info in port_info.items():
                        self.port_tree.insert(
                            '',
                            'end',
                            values=(
                                port,
                                info.get('service', 'Noma\'lum'),
                                info.get('remote_ip', 'Noma\'lum'),
                                info.get('remote_host', 'Noma\'lum'),
                                info.get('state', 'Noma\'lum')
                            )
                        )
                    
                    # Qo'shimcha ma'lumotlarni asosiy jadvalga qo'shish
                    self.tree.insert('', 'end', values=(
                        'Ochiq Portlar Soni',
                        len([p for p, i in port_info.items() if i.get('state') == 'Ochiq'])
                    ))
                    
                    break
            
            if not device_found:
                self.tree.insert('', 'end', values=('Status', 'Qurilma tarmoqda topilmadi'))
                
        except Exception as e:
            messagebox.showerror("Xato", f"Xatolik yuz berdi: {str(e)}")
        
        self.is_scanning = False
        self.search_btn.config(state='normal')
    
    def scan_network(self):
        self.network_tree.delete(*self.network_tree.get_children())
        
        try:
            result = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.0/24"), timeout=3, verbose=0)[0]
            
            for sent, received in result:
                ip = received.psrc
                mac = received.hwsrc
                vendor = self.get_vendor_by_mac(mac)
                
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except:
                    hostname = "Noma'lum"
                
                open_ports = self.get_open_ports(ip)
                
                self.network_tree.insert(
                    '', 
                    'end',
                    values=(
                        ip,
                        mac,
                        vendor,
                        hostname,
                        ', '.join(map(str, open_ports)) if open_ports else "Yopiq"
                    )
                )
                
        except Exception as e:
            messagebox.showerror("Xato", f"Xatolik yuz berdi: {str(e)}")
        
        self.is_scanning = False
        self.scan_btn.config(state='normal')
    
    def start_search(self):
        if not self.is_scanning:
            self.is_scanning = True
            self.search_btn.config(state='disabled')
            
            search_thread = threading.Thread(target=self.search_device)
            search_thread.daemon = True
            search_thread.start()
    
    def start_network_scan(self):
        if not self.is_scanning:
            self.is_scanning = True
            self.scan_btn.config(state='disabled')
            
            scan_thread = threading.Thread(target=self.scan_network)
            scan_thread.daemon = True
            scan_thread.start()
    
    def run(self):
        self.root.mainloop()
    
    def get_available_macs(self):
        """Mavjud tarmoq qurilmalarining MAC manzillarini olish"""
        macs = set()
        try:
            # ARP jadvali orqali MAC manzillarni olish
            arp = ARP(pdst="192.168.1.0/24")
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            result = srp(ether/arp, timeout=2, verbose=0)[0]
            
            for sent, received in result:
                mac = received.hwsrc
                vendor = self.get_vendor_by_mac(mac)
                macs.add(f"{mac} - {vendor}")
            
            # Local interfacelar MAC manzillarini qo'shish
            for interface in netifaces.interfaces():
                try:
                    addrs = netifaces.ifaddresses(interface)
                    if netifaces.AF_LINK in addrs:
                        mac = addrs[netifaces.AF_LINK][0]['addr']
                        vendor = self.get_vendor_by_mac(mac)
                        macs.add(f"{mac} - {vendor}")
                except:
                    continue
                    
        except Exception as e:
            print(f"MAC manzillarni olishda xatolik: {e}")
        
        return sorted(list(macs))
    
    def format_mac(self, event=None):
        """MAC manzilni formatlash"""
        mac = self.mac_var.get().upper()
        
        # Faqat raqam va harflarni qoldirish
        mac = re.sub(r'[^A-F0-9]', '', mac)
        
        # Har 2 ta belgidan keyin : qo'yish
        formatted_mac = ':'.join([mac[i:i+2] for i in range(0, len(mac), 2) if i < 12])
        
        # Kursorning joriy pozitsiyasini saqlash
        cursor_pos = self.mac_combo.index(tk.INSERT)
        
        # Yangi formatdagi MAC ni o'rnatish
        self.mac_var.set(formatted_mac)
        
        # Kursorni qaytarish
        self.mac_combo.icursor(cursor_pos)
    
    def on_mac_selected(self, event=None):
        """Combobox'dan MAC tanlanganda"""
        selected = self.mac_var.get()
        if ' - ' in selected:
            # Vendor qismini olib tashlash
            mac = selected.split(' - ')[0]
            self.mac_var.set(mac)
    
    def refresh_macs(self):
        """MAC manzillar ro'yxatini yangilash"""
        self.available_macs = self.get_available_macs()
        self.mac_combo['values'] = self.available_macs
        messagebox.showinfo("Ma'lumot", "MAC manzillar ro'yxati yangilandi")

if __name__ == "__main__":
    app = MACScanner()
    app.run() 