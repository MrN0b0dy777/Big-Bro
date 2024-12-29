import ctypes
import sys
import os
import psutil
import time
import tkinter as tk
from tkinter import ttk, messagebox
from plyer import notification
from threading import Thread
import requests
from ipaddress import ip_network, ip_address as ip_addr
import socket
import time
from pystray import Icon, MenuItem, Menu
from PIL import Image, ImageDraw
import winsound
from win10toast import ToastNotifier
import json
from PIL import Image, ImageTk
from concurrent.futures import ThreadPoolExecutor
import socket
from threading import Thread
from threading import Thread
from queue import Queue



# Cloudflare IP ünvanlarının siyahısı
CLOUDFLARE_IPS = [
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22"
]
notifier = ToastNotifier()

def send_notification(title, message):
    # Skriptin yerləşdiyi qovluğu tapırıq
    BASE_DIR = os.path.dirname(os.path.abspath(sys.argv[0]))

    # Faylın tam yolunu təyin edirik
    icon_path = os.path.join(BASE_DIR, "eye.ico")

    # Faylın mövcudluğunu yoxlayırıq
    if not os.path.exists(icon_path):
        print(f"Icon file not found: {icon_path}")
        icon_path = None  # İkon tapılmasa, sadəcə bildiriş göndərin

    # Bildiriş göndəririk
    notifier.show_toast(title, message, duration=10, icon_path=icon_path)
# Fayl adları
BIG_BRO_DIR = r"C:\Big Bro"
VIRUSTOTAL_API_KEY_FILE = os.path.join(BIG_BRO_DIR, "virustotal_api_key.txt")
ABUSEIPDB_API_KEY_FILE = os.path.join(BIG_BRO_DIR, "abuseipdb_api_key.txt")
if not os.path.exists(BIG_BRO_DIR):
    os.makedirs(BIG_BRO_DIR)
# Fayldan API açarlarını oxumaq və saxlamaq
def load_api_key(file_path):
    """ API açarını fayldan oxuyur """
    if os.path.exists(file_path):
        with open(file_path, "r") as file:
            return file.read().strip()
    return ""

def save_api_key(api_key, file_path):
    """ API açarını faylda saxlayır """
    with open(file_path, "w") as file:
        file.write(api_key)

# Global API açarlarını yükləyirik
VIRUSTOTAL_API_KEY = load_api_key(VIRUSTOTAL_API_KEY_FILE)
ABUSEIPDB_API_KEY = load_api_key(ABUSEIPDB_API_KEY_FILE)
LIST_DIR = r"C:\Big Bro\ip_lists"  # Faylların saxlanacağı qovluq
MALICIOUS_FILE = os.path.join(LIST_DIR, "malicious_ips.txt")
SUSPICIOUS_FILE = os.path.join(LIST_DIR, "suspicious_ips.txt")
CLEAN_FILE = os.path.join(LIST_DIR, "clean_ips.txt")
TELEGRAM_BOT_TOKEN_FILE = os.path.join(BIG_BRO_DIR, "telegram_bot_token.txt")
TELEGRAM_BOT_CHAT_ID_FILE = os.path.join(BIG_BRO_DIR, "telegram_bot_chat_id.txt")
# Proqram başladığında dəyərləri yükləyirik
def load_telegram_data(file_path_token, file_path_chat):
    """ Bot token və chat id-ni fayldan oxuyur və `******-******-******-******-******` kimi göstərir """
    bot_token, chat_id = "", ""
    
    if os.path.exists(file_path_token):
        with open(file_path_token, "r") as file:
            bot_token = file.read().strip()
    
    if os.path.exists(file_path_chat):
        with open(file_path_chat, "r") as file:
            chat_id = file.read().strip()
    
    # Fayldan oxunan real dəyərləri qaytarır
    return bot_token, chat_id



def save_telegram_data(bot_token, chat_id, file_path_token, file_path_chat):
    """ Bot token və chat id-ni faylda saxlamaq """
    with open(file_path_token, "w") as file:
        file.write(bot_token)
    
    with open(file_path_chat, "w") as file:
        file.write(chat_id)
# Admin hüquqları ilə işləmə funksiyası
def run_as_admin():
    """ Relaunch the script as admin if not already running as admin """
    if not is_admin():
        script = sys.argv[0]
        params = " ".join(sys.argv[1:])
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{script}" {params}', None, 1)
        sys.exit(0)

def is_admin():
    """ Check if the script is running as admin """
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

if not is_admin():
    run_as_admin()

# Əvvəlki əlaqələri saxlamaq üçün set yaradılır
previous_connections = set()
last_connection = None
process_info = {}  # Proses məlumatlarını saxlamaq üçün əlavə bir lüğət
all_rows = []  # Backup of all rows in the table

# İstisna edilmiş IP-lərin siyahısı
EXCLUDED_IPS = {"127.0.0.1", "8.8.8.8", "8.8.4.4", "4.4.4.4"}
def create_tray_icon(root, show_callback, exit_callback):
    # Skriptin yerləşdiyi qovluğu tapırıq
    BASE_DIR = os.path.dirname(os.path.abspath(sys.argv[0]))

    # Faylın tam yolunu təyin edirik
    icon_path = os.path.join(BASE_DIR, "eye.ico")

    # Faylın mövcudluğunu yoxlayırıq
    if not os.path.exists(icon_path):
        print(f"Icon file not found: {icon_path}")
        sys.exit(1)  # Xəta ilə çıxış

    # İkonu yükləyirik
    image = Image.open(icon_path)

    def on_show(icon, item):
        show_callback(icon)

    def on_exit(icon, item):
        exit_callback(icon)

    menu = Menu(
        MenuItem("Show", on_show),
        MenuItem("Exit", on_exit)
    )

    tray_icon = Icon("BigBro", image, "Big Bro Monitor", menu)
    return tray_icon
def load_ip_list(file_path):
    if os.path.exists(file_path):
        with open(file_path, "r") as f:
            return set(f.read().splitlines())
    return set()

# Siyahıları saxla
def save_ip_list(ip_list, file_path):
    with open(file_path, "w") as f:
        f.write("\n".join(ip_list))

# Siyahıları yükləyirik
malicious_ips = load_ip_list(MALICIOUS_FILE)
suspicious_ips = load_ip_list(SUSPICIOUS_FILE)
clean_ips = load_ip_list(CLEAN_FILE)

# Qovluğu yaradın
if not os.path.exists(LIST_DIR):
    os.makedirs(LIST_DIR)
# Network Card Selector GUI
class NetworkCardSelector:
    def __init__(self, root):
        self.root = root
        self.root.title("Big Bro")

        # Skriptin yerləşdiyi qovluğu tapırıq
        BASE_DIR = os.path.dirname(os.path.abspath(sys.argv[0]))

        # Faylın tam yolunu təyin edirik
        icon_path = os.path.join(BASE_DIR, "eye.ico")

        # Faylın mövcudluğunu yoxlayırıq
        if not os.path.exists(icon_path):
            print(f"Icon file not found: {icon_path}")
            icon_path = None  # Fayl tapılmasa, ikon istifadə olunmayacaq

        # Dinamik ikon təyin edirik
        if icon_path:
            self.root.iconbitmap(icon_path)

        window_width = 500  # Genişlik
        window_height = 620  # Hündürlük

        # Ekran ölçülərini əldə edin
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()

        # Mərkəz koordinatlarını hesablayın
        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 2

        # Yeni ölçüləri tətbiq edin və mərkəzləşdirin
        self.root.geometry(f"{window_width}x{window_height}+{x}+{y}")
        self.root.configure(bg="#2e2e2e")

        self.title_label = tk.Label(self.root, text="Select Network Interface", font=("Arial", 16), bg="#2e2e2e", fg="#ffffff")
        self.title_label.pack(pady=20)

        self.adapters = self.get_network_adapters()

        self.adapter_var = tk.StringVar()
        self.adapter_dropdown = ttk.Combobox(self.root, textvariable=self.adapter_var, font=("Arial", 12))
        self.adapter_dropdown["values"] = self.adapters
        self.adapter_dropdown.pack(pady=10)
        self.adapter_dropdown.current(0)

        self.select_button = tk.Button(self.root, text="Start Monitoring", font=("Arial", 12), bg="#016c87", fg="#ffffff", command=self.start_monitoring)
        self.select_button.pack(pady=20)
        self.root.protocol("WM_DELETE_WINDOW", self.minimize_to_tray)
        
        self.api_label = tk.Label(self.root, text="Enter VirusTotal API Key:", font=("Arial", 12), bg="#2e2e2e", fg="#dcdcdc")
        self.api_label.pack(pady=5)

        self.api_entry = tk.Entry(self.root, font=("Arial", 12), width=30, bg="#424242", fg="#ffffff", insertbackground="#ffffff")
        self.api_entry.pack(pady=5)
        if VIRUSTOTAL_API_KEY:
            self.api_entry.insert(0, "******-******-******-******-******")

        # Frame for VirusTotal buttons
        api_button_frame = tk.Frame(self.root, bg="#2e2e2e")
        api_button_frame.pack(pady=5)

        self.save_api_button = tk.Button(api_button_frame, text="Save API Key", font=("Arial", 10), command=self.save_api_key, bg="#00661d", fg="#ffffff", relief="flat")
        self.save_api_button.pack(side="left", padx=5)

        self.delete_api_button = tk.Button(api_button_frame, text="Delete API Key", font=("Arial", 10), command=self.delete_api_key, bg="#830000", fg="#ffffff", relief="flat")
        self.delete_api_button.pack(side="left", padx=5)

        # === AbuseIPDB API Key Section ===
        self.abuse_api_label = tk.Label(self.root, text="Enter AbuseIPDB API Key:", font=("Arial", 12), bg="#2e2e2e", fg="#dcdcdc")
        self.abuse_api_label.pack(pady=5)

        self.abuse_api_entry = tk.Entry(self.root, font=("Arial", 12), width=30, bg="#424242", fg="#ffffff", insertbackground="#ffffff")
        self.abuse_api_entry.pack(pady=5)
        if ABUSEIPDB_API_KEY:
            self.abuse_api_entry.insert(0, "******-******-******-******-******")

        # Frame for AbuseIPDB buttons
        abuse_api_button_frame = tk.Frame(self.root, bg="#2e2e2e")
        abuse_api_button_frame.pack(pady=5)

        self.save_abuse_api_button = tk.Button(abuse_api_button_frame, text="Save AbuseAPI Key", font=("Arial", 10), command=self.save_abuse_api_key, bg="#00661d", fg="#ffffff", relief="flat")
        self.save_abuse_api_button.pack(side="left", padx=5)

        self.delete_abuse_api_button = tk.Button(abuse_api_button_frame, text="Delete AbuseAPI Key", font=("Arial", 10), command=self.delete_abuse_api_key, bg="#830000", fg="#ffffff", relief="flat")
        self.delete_abuse_api_button.pack(side="left", padx=5)

        # Telegram Bot Token Section
        self.bot_token_label = tk.Label(self.root, text="Enter Bot Token:", font=("Arial", 12), bg="#2e2e2e", fg="#dcdcdc")
        self.bot_token_label.pack(pady=5)

        self.bot_token_entry = tk.Entry(self.root, font=("Arial", 12), width=30, bg="#424242", fg="#ffffff", insertbackground="#ffffff")
        self.bot_token_entry.pack(pady=5)

        bot_token_button_frame = tk.Frame(self.root, bg="#2e2e2e")
        bot_token_button_frame.pack(pady=5)

        self.save_bot_token_button = tk.Button(bot_token_button_frame, text="Save Bot Token", font=("Arial", 10), command=self.save_bot_token, bg="#00661d", fg="#ffffff", relief="flat")
        self.save_bot_token_button.pack(side="left", padx=5)

        self.delete_bot_token_button = tk.Button(bot_token_button_frame, text="Delete Bot Token", font=("Arial", 10), command=self.delete_bot_token, bg="#830000", fg="#ffffff", relief="flat")
        self.delete_bot_token_button.pack(side="left", padx=5)
        

        # Chat ID Section
        self.chat_id_label = tk.Label(self.root, text="Enter Chat ID:", font=("Arial", 12), bg="#2e2e2e", fg="#dcdcdc")
        self.chat_id_label.pack(pady=5)

        self.chat_id_entry = tk.Entry(self.root, font=("Arial", 12), width=30, bg="#424242", fg="#ffffff", insertbackground="#ffffff")
        self.chat_id_entry.pack(pady=5)

        chat_id_button_frame = tk.Frame(self.root, bg="#2e2e2e")
        chat_id_button_frame.pack(pady=5)

        self.save_chat_id_button = tk.Button(chat_id_button_frame, text="Save Chat ID", font=("Arial", 10), command=self.save_chat_id, bg="#00661d", fg="#ffffff", relief="flat")
        self.save_chat_id_button.pack(side="left", padx=5)

        self.delete_chat_id_button = tk.Button(chat_id_button_frame, text="Delete Chat ID", font=("Arial", 10), command=self.delete_chat_id, bg="#830000", fg="#ffffff", relief="flat")
        self.delete_chat_id_button.pack(side="left", padx=5)
                # Telegram bot token və chat ID-ni fayldan oxuyuruq
        # Telegram bot token və chat ID-ni fayldan oxuyuruq
        bot_token, chat_id = load_telegram_data(TELEGRAM_BOT_TOKEN_FILE, TELEGRAM_BOT_CHAT_ID_FILE)

        # Fayldan oxunan dəyərləri gizli formatda (`******-******-******-******-******`) daxil edirik
        if bot_token:
            self.bot_token_entry.delete(0, tk.END)
            self.bot_token_entry.insert(0, "******-******-******-******-******")
        if chat_id:
            self.chat_id_entry.delete(0, tk.END)
            self.chat_id_entry.insert(0, "******-******-******-******-******")


    def get_network_adapters(self):
        return list(psutil.net_if_addrs().keys())

    def start_monitoring(self):
        selected_adapter = self.adapter_var.get()
        if selected_adapter not in self.adapters:
            tk.messagebox.showerror("Error", "Invalid adapter selected!")
            return
        self.root.withdraw()

        # Yeni pəncərə yaradılır
        new_window = tk.Toplevel(self.root)
        new_window.title("Monitoring Connections")

        # Skriptin yerləşdiyi qovluğu tapırıq
        BASE_DIR = os.path.dirname(os.path.abspath(sys.argv[0]))

        # Faylın tam yolunu təyin edirik
        icon_path = os.path.join(BASE_DIR, "eye.ico")

        # Faylın mövcudluğunu yoxlayırıq
        if not os.path.exists(icon_path):
            print(f"Icon file not found: {icon_path}")
            icon_path = None  # Fayl tapılmasa, ikon istifadə olunmayacaq

        # Dinamik ikon təyin edirik
        if icon_path:
            new_window.iconbitmap(icon_path)

        # Yeni pəncərənin ölçülərini təyin edirik
        new_window.geometry("1024x900")  # Pəncərənin ölçüsü
        new_window.configure(bg="#2e2e2e")

        # Ekranın ölçülərini əldə edirik
        screen_width = new_window.winfo_screenwidth()
        screen_height = new_window.winfo_screenheight()

        # Mərkəzinə yerləşdiririk
        x = (screen_width - 1024) // 2  # Pəncərəni tam mərkəzə yerləşdiririk
        y = (screen_height - 900) // 2  # Pəncərəni tam mərkəzə yerləşdiririk

        # Yeni pəncərəni mərkəzdə yerləşdiririk
        new_window.geometry(f"1024x900+{x}+{y}")

        # Yeni pəncərədə tətbiqi işə salırıq
        app = ConnectionMonitorApp(new_window, selected_adapter)








    def minimize_to_tray(self):
        """ Pəncərəni tray ikonuna göndər """
        self.root.withdraw()  # Pəncərəni gizlədin
        tray_icon = create_tray_icon(self.root)  # Tray ikonunu yaradın
        Thread(target=tray_icon.run, daemon=True).start()
    def save_api_key(self):
        global VIRUSTOTAL_API_KEY
        VIRUSTOTAL_API_KEY = self.api_entry.get()
        save_api_key(VIRUSTOTAL_API_KEY, VIRUSTOTAL_API_KEY_FILE)
        self.api_entry.delete(0, tk.END)
        self.api_entry.insert(0, "******-******-******-******-******")
        messagebox.showinfo("API Key Saved", "VirusTotal API key has been saved.")
    
    
    def save_bot_token(self):
        bot_token = self.bot_token_entry.get()
        if bot_token:  # Boş olmadığını yoxlayırıq
            with open(TELEGRAM_BOT_TOKEN_FILE, "w") as file:
                file.write(bot_token)
            # Dəyəri saxladıqdan sonra `Entry` sahəsini yeniləyirik
            self.bot_token_entry.delete(0, tk.END)
            self.bot_token_entry.insert(0, "******-******-******-******-******")
            messagebox.showinfo("Bot Token Saved", "Bot Token has been saved.")
        else:
            messagebox.showerror("Error", "Bot Token cannot be empty.")


    def save_chat_id(self):
        chat_id = self.chat_id_entry.get()
        if chat_id:  # Boş olmadığını yoxlayırıq
            with open(TELEGRAM_BOT_CHAT_ID_FILE, "w") as file:
                file.write(chat_id)
            # Dəyəri saxladıqdan sonra `Entry` sahəsini yeniləyirik
            self.chat_id_entry.delete(0, tk.END)
            self.chat_id_entry.insert(0, "******-******-******-******-******")
            messagebox.showinfo("Chat ID Saved", "Chat ID has been saved.")
        else:
            messagebox.showerror("Error", "Chat ID cannot be empty.")


    def delete_bot_token(self):
        if os.path.exists(TELEGRAM_BOT_TOKEN_FILE):
            os.remove(TELEGRAM_BOT_TOKEN_FILE)
        self.bot_token_entry.delete(0, tk.END)
        messagebox.showinfo("Deleted", "Bot Token has been deleted.")

    def delete_chat_id(self):
        if os.path.exists(TELEGRAM_BOT_CHAT_ID_FILE):
            os.remove(TELEGRAM_BOT_CHAT_ID_FILE)
        self.chat_id_entry.delete(0, tk.END)
        messagebox.showinfo("Deleted", "Chat ID has been deleted.")



    TELEGRAM_BOT_TOKEN_FILE = os.path.join(BIG_BRO_DIR, "telegram_bot_token.txt")
    TELEGRAM_BOT_CHAT_ID_FILE = os.path.join(BIG_BRO_DIR, "telegram_bot_chat_id.txt")

    def load_bot_token():
        return load_api_key(TELEGRAM_BOT_TOKEN_FILE)

    def load_chat_id():
        return load_api_key(TELEGRAM_BOT_CHAT_ID_FILE)

    def delete_api_key(self):
        """ VirusTotal API açarını silmək """
        global VIRUSTOTAL_API_KEY
        VIRUSTOTAL_API_KEY = ""
        self.api_entry.delete(0, tk.END)
        os.remove(VIRUSTOTAL_API_KEY_FILE)  # API açarını fayldan silmək
        messagebox.showinfo("API Key Deleted", "VirusTotal API key has been deleted.")

    def save_abuse_api_key(self):
        global ABUSEIPDB_API_KEY
        ABUSEIPDB_API_KEY = self.abuse_api_entry.get()
        save_api_key(ABUSEIPDB_API_KEY, ABUSEIPDB_API_KEY_FILE)
        self.abuse_api_entry.delete(0, tk.END)
        self.abuse_api_entry.insert(0, "******-******-******-******-******")
        messagebox.showinfo("API Key Saved", "AbuseIPDB API key has been saved.")

    def delete_abuse_api_key(self):
        """ AbuseIPDB API açarını silmək """
        global ABUSEIPDB_API_KEY
        ABUSEIPDB_API_KEY = ""
        self.abuse_api_entry.delete(0, tk.END)
        os.remove(ABUSEIPDB_API_KEY_FILE)  # API açarını fayldan silmək
        messagebox.showinfo("API Key Deleted", "AbuseIPDB API key has been deleted.")
    def close_program_or_tray(self):
        """Pəncərəni tray rejiminə keçir və ya tamamilə bağlayır"""
        answer = messagebox.askyesno(
            "Exit", "Do you want to close the application completely?"
        )
        if answer:  # Əgər istifadəçi "Yes" seçərsə
            self.running = False
            self.root.destroy()
            sys.exit()
        else:  # Əks halda tray rejimə keçir
            self.hide_to_tray()

# GUI yaratmaq üçün tkinter istifadə edirik
class ConnectionMonitorApp:
    def __init__(self, root, adapter):
        self.start_time = time.time()
        self.root = root
        self.adapter = adapter
        self.running = True
        self.root.title("Big Bro")
        BASE_DIR = os.path.dirname(os.path.abspath(sys.argv[0]))

        # Faylın tam yolunu təyin edirik
        icon_path = os.path.join(BASE_DIR, "eye.ico")

        # Faylın mövcudluğunu yoxlayırıq
        if not os.path.exists(icon_path):
            print(f"Icon file not found: {icon_path}")
            icon_path = None  # Fayl tapılmasa, ikon istifadə olunmayacaq

        # Pəncərə başlığını və parametrlərini təyin edirik
        self.root.title("Big Bro")

        # Dinamik ikon təyin edirik
        if icon_path:
            self.root.iconbitmap(icon_path)

        window_width = 1300  # Pəncərənin genişliyini 1300 təyin edirik
        window_height = 900  # Pəncərənin hündürlüyü 900

        self.root.geometry(f"{self.root.winfo_screenwidth()}x{self.root.winfo_screenheight()}")
        self.root.state("zoomed")  # Tam ekran rejimi

        # Ekranın ölçülərini əldə edirik
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()

        # Mərkəzinə yerləşdiririk
        x = (screen_width - window_width) // 2  # Pəncərəni ekranın ortasına yerləşdiririk
        y = (screen_height - window_height) // 2  # Pəncərəni ekranın ortasına yerləşdiririk

        # Yeni pəncərəni mərkəzdə yerləşdiririk
        self.root.geometry(f"{window_width}x{window_height}+{x}+{y}")

        # Pəncərəni və rəngini təyin edirik
        self.root.configure(bg="#2e2e2e")

        # Title
        self.title_label = tk.Label(self.root, text=f"Monitoring: {adapter}", font=("Arial", 18, 'bold'), bg="#2e2e2e", fg="#ffffff")
        self.title_label.pack(pady=20)

        # IP və Port bölmələri üçün bir frame yaradın
        # IP və Port bölmələri üçün bir frame yaradın
        search_frame = tk.Frame(self.root, bg="#2e2e2e")
        search_frame.pack(pady=10)

        # IP bölməsi
        self.search_ip_label = tk.Label(search_frame, text="Search by IP:", font=("Arial", 12), bg="#2e2e2e", fg="#dcdcdc")
        self.search_ip_label.grid(row=0, column=0, padx=5)

        self.search_ip_entry = tk.Entry(search_frame, font=("Arial", 12), width=15, bg="#424242", fg="#ffffff", insertbackground="#ffffff")
        self.search_ip_entry.grid(row=0, column=1, padx=5)

        self.search_ip_button = tk.Button(search_frame, text="Filter by IP", font=("Arial", 10), command=self.filter_by_ip, bg="#016c87", fg="#ffffff", relief="flat")
        self.search_ip_button.grid(row=0, column=2, padx=5)

        self.clear_ip_button = tk.Button(search_frame, text="Clear IP Filter", font=("Arial", 10), command=self.clear_ip_filter, bg="#016c87", fg="#ffffff", relief="flat")
        self.clear_ip_button.grid(row=0, column=3, padx=5)

        # Port bölməsi - eyni sırada
        self.search_port_label = tk.Label(search_frame, text="Search by Port:", font=("Arial", 12), bg="#2e2e2e", fg="#dcdcdc")
        self.search_port_label.grid(row=0, column=4, padx=20)  # Arada məsafə üçün padx artırılır

        self.search_port_entry = tk.Entry(search_frame, font=("Arial", 12), width=15, bg="#424242", fg="#ffffff", insertbackground="#ffffff")
        self.search_port_entry.grid(row=0, column=5, padx=5)

        self.search_port_button = tk.Button(search_frame, text="Filter by Port", font=("Arial", 10), command=self.filter_by_port, bg="#016c87", fg="#ffffff", relief="flat")
        self.search_port_button.grid(row=0, column=6, padx=5)

        self.clear_port_button = tk.Button(search_frame, text="Clear Port Filter", font=("Arial", 10), command=self.clear_port_filter, bg="#016c87", fg="#ffffff", relief="flat")
        self.clear_port_button.grid(row=0, column=7, padx=5)
    


        # Treeview table to show connection details
        self.tree = ttk.Treeview(
            self.root,
            columns=("IP", "Port", "Protocol", "Process", "Country", "Cloudflare", "VirusTotal", "AbuseIPDB", "Whois", "Bro Scan"),
            show="headings",
            height=15
        )


        # Treeview üçün xüsusi tag konfiqurasiyası
        style = ttk.Style()
        style.configure("Treeview", rowheight=25)

        # Treeview üçün tag-ları təyin edirik (rənglər açıq göy olur)
        self.tree.tag_configure("virustotal_col", foreground="#4682B4")  # Açıq mavi rəng
        self.tree.tag_configure("abuseipdb_col", foreground="#4682B4")  # Açıq mavi rəng
        self.tree.tag_configure("whois_col", foreground="#4682B4")       # Açıq mavi rəng
        self.tree.tag_configure("broscan_col", foreground="#4682B4")    # Açıq mavi rəng








        
        self.tree.pack(pady=10)
        self.tree.bind("<Button-1>", self.handle_action_click)
                # Checkbox Frame
        self.checkbox_frame = tk.Frame(self.root, bg="#2e2e2e")
        self.checkbox_frame.pack(pady=10)

        # Variables for Checkboxes
        self.all_events_var = tk.BooleanVar(value=False)
        self.suspicious_var = tk.BooleanVar(value=True)
        self.only_malicious_var = tk.BooleanVar(value=False)  # Yeni checkbox üçün dəyişən

        # All Events Checkbox
        self.all_events_checkbox = tk.Checkbutton(
            self.checkbox_frame, text="All Events", variable=self.all_events_var, bg="#2e2e2e", fg="#ffffff",
            selectcolor="#2e2e2e", activebackground="#2e2e2e", activeforeground="#ffffff", command=self.update_checkboxes
        )
        self.all_events_checkbox.pack(side="left", padx=10)

        # Only Suspicious and Malicious Checkbox
        self.suspicious_checkbox = tk.Checkbutton(
            self.checkbox_frame, text="Only Suspicious and Malicious", variable=self.suspicious_var, bg="#2e2e2e", fg="#ffffff",
            selectcolor="#2e2e2e", activebackground="#2e2e2e", activeforeground="#ffffff", command=self.update_checkboxes
        )
        self.suspicious_checkbox.pack(side="left", padx=10)

        # Only Malicious Checkbox
        self.only_malicious_checkbox = tk.Checkbutton(
            self.checkbox_frame, text="Only Malicious", variable=self.only_malicious_var, bg="#2e2e2e", fg="#ffffff",
            selectcolor="#2e2e2e", activebackground="#2e2e2e", activeforeground="#ffffff", command=self.update_checkboxes
        )

        self.only_malicious_checkbox.pack(side="left", padx=10)


        # Adjusting the padding for each column in the table
        self.tree.heading("IP", text="IP Address", anchor="w", command=lambda: self.sort_treeview("IP"))
        self.tree.heading("Port", text="Port", anchor="w", command=lambda: self.sort_treeview("Port"))
        self.tree.heading("Protocol", text="Protocol", anchor="w", command=lambda: self.sort_treeview("Protocol"))
        self.tree.heading("Process", text="Process", anchor="w", command=lambda: self.sort_treeview("Process"))
        self.tree.heading("Country", text="Country", anchor="w", command=lambda: self.sort_treeview("Country"))
        self.tree.heading("Cloudflare", text="Cloudflare", anchor="w", command=lambda: self.sort_treeview("Cloudflare"))
        self.tree.heading("VirusTotal", text="VirusTotal", anchor="w", command=lambda: self.sort_treeview("VirusTotal"))
        self.tree.heading("AbuseIPDB", text="AbuseIPDB", anchor="w", command=lambda: self.sort_treeview("AbuseIPDB"))
        self.tree.heading("Whois", text="Whois", anchor="w", command=lambda: self.sort_treeview("Whois"))
        self.tree.heading("Bro Scan", text="Bro Scan", anchor="w", command=lambda: self.sort_treeview("Bro Scan"))



        # Setting column widths and padding
        self.tree.column("IP", width=150, anchor="w")
        self.tree.column("Port", width=100, anchor="w")
        self.tree.column("Protocol", width=100, anchor="w")
        self.tree.column("Process", width=150, anchor="w")
        self.tree.column("Country", width=150, anchor="w")
        self.tree.column("Cloudflare", width=100, anchor="w")
        self.tree.column("VirusTotal", width=120, anchor="w")
        self.tree.column("AbuseIPDB", width=120, anchor="w")
        self.tree.column("Whois", width=120, anchor="w")
        self.tree.column("Bro Scan", width=150, anchor="w")


        # Adding padding for the cell text
        style = ttk.Style()
        style.configure("Treeview", padding=10)

        # Scrollbar for the Treeview table
        self.scrollbar = tk.Scrollbar(self.root, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.scrollbar.pack(side=tk.TOP, fill=tk.X)

        # Link scrollbar with TreeviewFkil
        self.tree.config(yscrollcommand=self.scrollbar.set)

        # Connection Status Label
        self.status_label = tk.Label(self.root, text="Big Bro can see everything...", font=("Arial", 12), bg="#2e2e2e", fg="#f90f00")
        self.status_label.pack(pady=10)
        button_frame_lists = tk.Frame(self.root, bg="#2e2e2e")
        button_frame_lists.pack(pady=5)

        self.malicious_button = tk.Button(
            button_frame_lists, text="Malicious List", font=("Arial", 12), bg="#830000", fg="#ffffff", command=self.show_malicious_list
        )
        self.malicious_button.pack(side="left", padx=5)

        self.suspicious_button = tk.Button(
            button_frame_lists, text="Suspicious List", font=("Arial", 12), bg="#d18700", fg="#ffffff", command=self.show_suspicious_list
        )
        self.suspicious_button.pack(side="left", padx=5)

        self.clean_button = tk.Button(
            button_frame_lists, text="Clean List", font=("Arial", 12), bg="#016c87", fg="#ffffff", command=self.show_clean_list
        )
        self.clean_button.pack(side="left", padx=5)

        # Button to Kill Connection
        button_frame = tk.Frame(self.root, bg="#2e2e2e")
        button_frame.pack(pady=15)
        self.kill_button = tk.Button(button_frame, text="Kill Connection", font=("Arial", 12), bg="#830000", fg="#ffffff", command=self.kill_connection, relief="raised")
        self.kill_button.pack(side="left", padx=10)

        # Button to Block IP
        self.block_button = tk.Button(button_frame, text="Block IP", font=("Arial", 12), bg="#830000", fg="#ffffff", command=self.block_ip, relief="raised")
        self.block_button.pack(side="left", padx=10)
        self.back_button = tk.Button(button_frame, text="Back", font=("Arial", 12), bg="#016c87", fg="#ffffff", command=self.go_back, relief="raised")
        self.back_button.pack(side="left", padx=10)

        # Start monitoring connections in a separate thread
        self.monitor_thread = Thread(target=self.monitor_connections)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()

        # Sorting functionality
        self.sorted_column = None
        self.reverse_sort = False

        self.root.protocol("WM_DELETE_WINDOW", self.hide_to_tray)
        self.tray_icon = None
        self.tree.config(yscrollcommand=self.scrollbar.set)
        self.scrollbar.config(command=self.tree.yview)




        
        
    def python_nmap_scan(self, ip, ports=range(1, 1024)):
            """
            Multithreading ilə port skaneri.
            """
            scan_results = []
            
            def scan_port(port):
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(0.2)
                        result = s.connect_ex((ip, port))
                        if result == 0:
                            try:
                                service = socket.getservbyport(port, "tcp")
                            except:
                                service = "Unknown"
                            return port, service
                except:
                    pass
                return None

            with ThreadPoolExecutor(max_workers=50) as executor:
                results = executor.map(scan_port, ports)

            for result in results:
                if result:
                    scan_results.append(result)

            return scan_results if scan_results else "No open ports found."

    def open_python_nmap(self, ip, ports=range(1, 1025)):
        """Python ilə yazılmış Nmap-ə alternativ skaneri işə salır və nəticələri göstərir."""
        nmap_window = tk.Toplevel(self.root)
        nmap_window.title(f"Bro Scan Results for {ip}")

        # Pəncərə ölçülərini təyin edin
        window_width = 600
        window_height = 400
        nmap_window.geometry(f"{window_width}x{window_height}")

        # Ekran ölçülərini əldə edin
        screen_width = nmap_window.winfo_screenwidth()
        screen_height = nmap_window.winfo_screenheight()

        # Koordinatları hesablayın ki, pəncərə mərkəzə yerləşsin
        x = (screen_width // 2) - (window_width // 2)
        y = (screen_height // 2) - (window_height // 2)

        # Yeni pəncərəni mərkəzə yerləşdirin
        nmap_window.geometry(f"{window_width}x{window_height}+{x}+{y}")
        nmap_window.configure(bg="#2e2e2e")

        # Faylın tam yolunu əldə edin
        icon_path = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), "eye.ico")

        # Fayl mövcuddursa, ikon əlavə edin
        if os.path.exists(icon_path):
            nmap_window.iconbitmap(icon_path)
        else:
            print(f"Icon file not found: {icon_path}")

        # Başlıq etiketi
        label = tk.Label(nmap_window, text=f"Bro Scan Results for {ip}", font=("Arial", 14), bg="#2e2e2e", fg="#ffffff")
        label.pack(pady=10)

        # Text area yaradılır
        text_area = tk.Text(nmap_window, font=("Courier", 10), bg="#424242", fg="#ffffff", wrap="word")
        text_area.pack(fill="both", expand=True, padx=10, pady=10)

        def run_python_nmap():
            # text_area-dan əvvəl mətn əlavə edirik
            text_area.insert("1.0", "Scanning in progress...\n")
            text_area.insert("1.0", "Please wait 5-10 minutes while the scan completes...\n")
            results = self.python_nmap_scan(ip, ports=ports)
            text_area.delete("1.0", "end")  # Əvvəlki mətn silinir
            if isinstance(results, str):
                text_area.insert("1.0", results)
            else:
                for port, service in results:
                    text_area.insert("end", f"Port {port}: {service}\n")
        
        Thread(target=run_python_nmap, daemon=True).start()

        # Pəncərəni bağlamaq üçün düymə
        close_button = tk.Button(nmap_window, text="Close", font=("Arial", 12), bg="#830000", fg="#ffffff", command=nmap_window.destroy)
        close_button.pack(pady=10)

        
        
        
    def ask_port_range(self, ip):
        """Port aralığını seçmək üçün pəncərə açır."""
        port_window = tk.Toplevel(self.root)
        port_window.title("Select Port Range")

        # Pəncərə ölçülərini təyin edin
        window_width = 300
        window_height = 150
        port_window.geometry(f"{window_width}x{window_height}")

        # Ekran ölçülərini əldə edin
        screen_width = port_window.winfo_screenwidth()
        screen_height = port_window.winfo_screenheight()

        # Koordinatları hesablayın ki, pəncərə mərkəzə yerləşsin
        x = (screen_width // 2) - (window_width // 2)
        y = (screen_height // 2) - (window_height // 2)

        # Yeni pəncərəni mərkəzə yerləşdirin
        port_window.geometry(f"{window_width}x{window_height}+{x}+{y}")
        port_window.configure(bg="#2e2e2e")

        # Faylın tam yolunu əldə edin
        icon_path = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), "eye.ico")

        # Fayl mövcuddursa, ikon əlavə edin
        if os.path.exists(icon_path):
            port_window.iconbitmap(icon_path)
        else:
            print(f"Icon file not found: {icon_path}")

        # Başlıq etiketi
        label = tk.Label(port_window, text="Select Port Range for Scanning", font=("Arial", 12), bg="#2e2e2e", fg="#ffffff")
        label.pack(pady=10)

        # Düymələr çərçivəsi
        button_frame = tk.Frame(port_window, bg="#2e2e2e")
        button_frame.pack(pady=10)

        # Port aralığı seçimi düymələri
        def scan_1024_ports():
            port_window.destroy()
            self.open_python_nmap(ip, ports=range(1, 1025))

        def scan_65536_ports():
            port_window.destroy()
            self.open_python_nmap(ip, ports=range(1, 65536))

        button_1024 = tk.Button(button_frame, text="1-1024", font=("Arial", 12), bg="#016c87", fg="#ffffff", command=scan_1024_ports)
        button_1024.pack(side="left", padx=5)

        button_65536 = tk.Button(button_frame, text="1-65536", font=("Arial", 12), bg="#016c87", fg="#ffffff", command=scan_65536_ports)
        button_65536.pack(side="left", padx=5)

        # Bağlama düyməsi
        close_button = tk.Button(port_window, text="Cancel", font=("Arial", 12), bg="#830000", fg="#ffffff", command=port_window.destroy)
        close_button.pack(pady=10)




        
        

                
    def add_row(self, ip, port, protocol, process, country, cloudflare, virustotal, abuseipdb, whois_info="Whois", bro_scan_info="Bro Scan"):
        """Treeview-a sətir əlavə edir və yalnız müəyyən sütunlara rəng tətbiq edir."""
        row_id = self.tree.insert(
            "",
            tk.END,
            values=(ip, port, protocol, process, country, cloudflare, virustotal, abuseipdb, whois_info, bro_scan_info)
        )

        # Yalnız xüsusi sütunlara rəng tətbiq edirik
        if virustotal and virustotal != "":
            self.tree.item(row_id, tags=("virustotal_col",))

        if abuseipdb and abuseipdb != "":
            self.tree.item(row_id, tags=("abuseipdb_col",))

        if whois_info and whois_info != "":
            self.tree.item(row_id, tags=("whois_col",))

        if bro_scan_info and bro_scan_info != "":
            self.tree.item(row_id, tags=("broscan_col",))











        
    def handle_action_click(self, event):
        # Klik edilən bölgəni və sütunu müəyyən edirik
        region = self.tree.identify_region(event.x, event.y)
        column = self.tree.identify_column(event.x)
        row_id = self.tree.identify_row(event.y)

        if not row_id:  # Əgər klik boş yerdirsə
            return

        # Əgər klik "Whois" sütununa olubsa
        if region == "cell" and column == "#9":  # "#9" Whois sütununun indeksi
            values = self.tree.item(row_id, "values")
            ip = values[0]  # IP ünvanını əldə edirik
            self.open_whois(ip)

        # Əgər klik "VirusTotal" sütununa olubsa
        elif region == "cell" and column == "#7":  # "#7" VirusTotal sütununun indeksi
            values = self.tree.item(row_id, "values")
            ip = values[0]  # IP ünvanını əldə edirik
            self.open_virustotal(ip)

        # Əgər klik "AbuseIPDB" sütununa olubsa
        elif region == "cell" and column == "#8":  # "#8" AbuseIPDB sütununun indeksi
            values = self.tree.item(row_id, "values")
            ip = values[0]
            self.open_abuseipdb(ip)

        # Əgər klik "Python Nmap" sütununa olubsa
        elif region == "cell" and column == "#10":  # "#10" Python Nmap sütununun indeksi
            values = self.tree.item(row_id, "values")
            ip = values[0]
            self.ask_port_range(ip)

    def get_whois_info(self, ip):
        """IP ünvanı üçün Whois məlumatlarını alır."""
        try:
            url = f"https://who.is/whois-ip/ip-address/{ip}"
            response = requests.get(url)
            if response.status_code == 200:
                # Whois məlumatlarını buradan çıxarıb qaytarırıq
                # Əgər lazımdırsa, HTML parse etmək və məlumatları çıxarmaq lazımdır
                return "Whois Info"  # Burada əsl məlumatı qaytarın
            else:
                return "No Whois Info"
        except Exception as e:
            return "Error"






    def open_whois(self, ip):
        """Whois saytını açır."""
        import webbrowser
        url = f"https://who.is/whois-ip/ip-address/{ip}"
        webbrowser.open_new_tab(url)



    def open_virustotal(self, ip):
        """VirusTotal saytını açır."""
        import webbrowser
        url = f"https://www.virustotal.com/gui/ip-address/{ip}"
        webbrowser.open_new_tab(url)   
        
    def open_abuseipdb(self, ip):
        """AbuseIPDB saytını açır."""
        import webbrowser
        url = f"https://www.abuseipdb.com/check/{ip}"
        webbrowser.open_new_tab(url)
       
       










    def send_telegram_alert(self, message):
        """
        Telegram botu vasitəsilə mesaj göndərir.
        Asinxron olaraq işləyir.
        """
        def send_message():
            bot_token = load_api_key(TELEGRAM_BOT_TOKEN_FILE)  # Bot token fayldan yüklənir
            chat_id = load_api_key(TELEGRAM_BOT_CHAT_ID_FILE)  # Chat ID fayldan yüklənir

            if not bot_token or not chat_id:
                print("Telegram üçün token və ya chat ID tapılmadı.")
                return

            url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
            payload = {"chat_id": chat_id, "text": message}

            try:
                response = requests.post(url, json=payload)
                if response.status_code != 200:
                    print(f"Telegram xətası: {response.status_code} - {response.text}")
                else:
                    print(f"Mesaj uğurla göndərildi: {message}")
            except Exception as e:
                print(f"Telegram mesajını göndərərkən xəta baş verdi: {e}")

        # Yeni bir yivdə (thread) mesaj göndəririk
        Thread(target=send_message, daemon=True).start()






                
    def hide_to_tray(self):
        self.root.withdraw()
        self.tray_icon = create_tray_icon(
        self.root,
        show_callback=self.show_window,
        exit_callback=self.exit_program
        )
        Thread(target=self.tray_icon.run, daemon=True).start()

    def show_window(self, icon):
        """ Show the monitoring window again """
        self.root.deiconify()
        icon.stop()  # Stop the tray icon loop

    def exit_program(self, icon):
        """ Exit the entire application """
        icon.stop()
        self.root.destroy()
        sys.exit()
    def show_list_window(self, title, ip_list):
        """Siyahıdakı IP-ləri yeni bir pəncərədə göstərir"""
        new_window = tk.Toplevel(self.root)
        new_window.title(title)

        # Pəncərə ölçüləri
        window_width = 400
        window_height = 600

        # Ekran ölçülərini əldə edirik
        screen_width = new_window.winfo_screenwidth()
        screen_height = new_window.winfo_screenheight()

        # Mərkəz koordinatlarını hesablayırıq
        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 2

        # Yeni koordinatları tətbiq edirik
        new_window.geometry(f"{window_width}x{window_height}+{x}+{y}")
        new_window.configure(bg="#2e2e2e")

        # Faylın yolunu yoxlayırıq və əlavə edirik
        icon_path = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), "eye.ico")
        if os.path.exists(icon_path):
            new_window.iconbitmap(icon_path)

        # Text area yaratmaq
        text_area = tk.Text(new_window, font=("Arial", 12), bg="#424242", fg="#ffffff", wrap="word")
        text_area.pack(fill="both", expand=True)

        # Məlumatları göstəririk
        text_area.insert("1.0", "\n".join(ip_list))
        text_area.config(state="disabled")  # Oxumaq üçün

        # Pəncərəni bağlama düyməsini əlavə edirik
        close_button = tk.Button(new_window, text="Close", font=("Arial", 12), bg="#830000", fg="#ffffff", command=new_window.destroy)
        close_button.pack(pady=10)




    def show_malicious_list(self):
        self.show_list_window("Malicious IPs", malicious_ips)

    def show_suspicious_list(self):
        self.show_list_window("Suspicious IPs", suspicious_ips)

    def show_clean_list(self):
        self.show_list_window("Clean IPs", clean_ips)

    # def get_url_from_ip(self, ip_address):
    #     """IP adresinden URL (hostname) bilgisini getirir."""
    #     try:
    #         return socket.gethostbyaddr(ip_address)[0]
    #     except socket.herror:
    #         return "Unknown"   
    def sort_treeview(self, column):
        if self.sorted_column == column:
            self.reverse_sort = not self.reverse_sort
        else:
            self.reverse_sort = False
            self.sorted_column = column

        # Sorting the Treeview based on the selected column
        items = [(self.tree.set(item, column), item) for item in self.tree.get_children('')]
        items.sort(key=lambda x: x[0], reverse=self.reverse_sort)

        # Re-inserting the sorted items back into the Treeview
        for index, item in enumerate(items):
            self.tree.move(item[1], '', index)

    # Filter and clear functions (you can define your own)
    def filter_by_ip(self):
        # Filtering logic for IP (you can customize this based on your requirements)
        pass

    def clear_ip_filter(self):
        # Clear IP filter logic
        pass

    def filter_by_port(self):
        # Filtering logic for Port
        pass

    def clear_port_filter(self):
        # Clear Port filter logic
        pass

    def kill_connection(self):
        # Logic for killing the connection
        pass

    def block_ip(self):
        # Logic for blocking the IP
        pass
    def go_back(self):
        """ Geri dönmək və monitorinqi dayandırmaq """
        self.running = False
        self.root.destroy()  # Cari pəncərəni bağlayırıq
        main_window.deiconify()
  # Cari pəncərəni bağlayırıq
      
    def monitor_connections(self):
        # Monitoring connections logic (this will run in a separate thread)
        pass

    def check_connections(self):
        global previous_connections, last_connection, process_info, all_rows

        for conn in psutil.net_connections(kind='inet'):
            if conn.raddr and conn.raddr.ip not in EXCLUDED_IPS:
                connection_tuple = (conn.raddr.ip, conn.raddr.port)

                if connection_tuple not in previous_connections:
                    previous_connections.add(connection_tuple)

                    # IP-nin təhlükəsizlik statusunu yoxlayırıq
                    ip_status = self.check_ip_safeness(conn.raddr.ip)
                    country = self.get_country(conn.raddr.ip)
                    cloudflare_status = self.is_cloudflare_ip(conn.raddr.ip)
                    abuseipdb_status = self.check_abuseipdb(conn.raddr.ip)
                    process_name = psutil.Process(conn.pid).name() if conn.pid else 'Unknown'
                    protocol = "UDP" if conn.type == socket.SOCK_DGRAM else "TCP"

                    # Əlaqə məlumatlarını əlavə edirik
                    process_info[connection_tuple] = (process_name, conn)
                    
                    # `Whois` sütununa hər zaman "Whois" dəyəri yazılır
                    whois_info = "Whois"
                    self.add_row(
                        conn.raddr.ip, conn.raddr.port, protocol, process_name,
                        country, cloudflare_status, ip_status, abuseipdb_status, whois_info
                    )





    def check_virustotal(self, ip_address):
        """IP ünvanını VirusTotal ilə yoxlamaq"""
        url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'
        headers = {
            'x-apikey': VIRUSTOTAL_API_KEY
        }
        try:
            response = requests.get(url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                malicious_count = data['data']['attributes']['last_analysis_stats']['malicious']
                if malicious_count >= 3:
                    return "Malicious"  # 3 və ya daha çox zərərli qeydiyyat
                elif malicious_count >= 1:
                    return "Suspicious"  # 1 və ya 2 zərərli qeydiyyat
                else:
                    return "Clean"  # Heç bir təhlükəli qeydiyyat yoxdur
            else:
                return "Error"
        except Exception as e:
            return "Error"

    def check_abuseipdb(self, ip_address):
        """IP ünvanını AbuseIPDB ilə yoxlamaq və cached nəticələri istifadə etmək."""
        global malicious_ips, suspicious_ips, clean_ips

        # Əgər IP cached siyahılardadırsa
        if ip_address in clean_ips:
            return "Low Risk"
        elif ip_address in malicious_ips:
            return "High Risk"
        elif ip_address in suspicious_ips:
            return "Medium Risk"

        # Siyahılarda deyilsə, AbuseIPDB ilə yoxlayırıq
        url = f'https://api.abuseipdb.com/api/v2/check'
        headers = {
            'Key': ABUSEIPDB_API_KEY,
            'Accept': 'application/json'
        }
        params = {'ipAddress': ip_address}

        try:
            response = requests.get(url, headers=headers, params=params)
            if response.status_code == 200:
                data = response.json()
                abuse_score = data['data']['abuseConfidenceScore']

                if abuse_score >= 80:
                    malicious_ips.add(ip_address)
                    save_ip_list(malicious_ips, MALICIOUS_FILE)
                    return f"High Risk ({abuse_score})"
                elif abuse_score >= 40:
                    suspicious_ips.add(ip_address)
                    save_ip_list(suspicious_ips, SUSPICIOUS_FILE)
                    return f"Medium Risk ({abuse_score})"
                else:
                    clean_ips.add(ip_address)
                    save_ip_list(clean_ips, CLEAN_FILE)
                    return f"Low Risk ({abuse_score})"
            else:
                return "Error"
        except Exception as e:
            return "Error"


    def check_ip_safeness(self, ip_address):
        """IP ünvanını VirusTotal və AbuseIPDB ilə yoxlamaq və cached nəticələri istifadə etmək."""
        global malicious_ips, suspicious_ips, clean_ips

        # Əgər IP artıq siyahılardadırsa
        if ip_address in clean_ips:
            return "Clean"
        elif ip_address in malicious_ips:
            return "Malicious"
        elif ip_address in suspicious_ips:
            return "Suspicious"

        # VirusTotal yoxlaması
        vt_result = self.check_virustotal(ip_address)
        if vt_result in ["Malicious", "Suspicious", "Clean"]:
            return vt_result

        # AbuseIPDB yoxlaması (VirusTotal nəticələri yoxdursa)
        abuse_result = self.check_abuseipdb(ip_address)
        return abuse_result

    def is_cloudflare_ip(self, ip_address):
        """IP ünvanının Cloudflare-ə aid olub olmadığını yoxlayır"""
        for network in CLOUDFLARE_IPS:
            if ip_addr(ip_address) in ip_network(network):
                return "Yes"
        return "No"

    def get_country(self, ip_address):
        """ IP ünvanından ölkə məlumatını almaq """
        try:
            response = requests.get(f'https://geolocation-db.com/json/{ip_address}&position=true').json()
            return response.get("country_name", "Unknown")
        except requests.exceptions.RequestException:
            return "Unknown"

    def monitor_connections(self):
        while self.running:
            try:
                if not self.tree.winfo_exists():  # Treeview mövcudluğunu yoxlayırıq
                    break
                self.check_connections()
                time.sleep(2)
            except Exception as e:
                print(f"Monitoring error: {e}")

    def filter_by_ip(self):
        """ IP ünvanına əsasən əlaqələri süzgəcdən keçirmək """
        search_ip = self.search_ip_entry.get()
        if search_ip:
            # Mövcud məlumatları təmizlə, amma `all_rows`-dan məlumatları silmə
            self.tree.delete(*self.tree.get_children())
            for row_id, values in all_rows:
                ip = values[0]
                if search_ip in ip:
                    self.tree.insert("", tk.END, iid=row_id, values=values, tags=("highlight_whois", "highlight_broscan", "highlight_virustotal", "highlight_abuseipdb"))


    def clear_ip_filter(self):
        """ IP filterini təmizləmək və əvvəlki məlumatları qaytarmaq """
        self.search_ip_entry.delete(0, tk.END)
        self.tree.delete(*self.tree.get_children())
        for row_id, values in all_rows:
            self.tree.insert("", tk.END, iid=row_id, values=values)

    def filter_by_port(self):
        """ Port nömrəsinə əsasən əlaqələri süzgəcdən keçirmək """
        search_port = self.search_port_entry.get()
        if search_port:
            # Mövcud məlumatları təmizlə, amma `all_rows`-dan məlumatları silmə
            self.tree.delete(*self.tree.get_children())
            for row_id, values in all_rows:
                port = str(values[1])  # Port nömrəsi
                if search_port in port:
                    self.tree.insert("", tk.END, iid=row_id, values=values, tags=("highlight_whois", "highlight_broscan", "highlight_virustotal", "highlight_abuseipdb"))


    def clear_port_filter(self):
        """ Port filterini təmizləmək və əvvəlki məlumatları qaytarmaq """
        self.search_port_entry.delete(0, tk.END)
        self.tree.delete(*self.tree.get_children())
        for row_id, values in all_rows:
            self.tree.insert("", tk.END, iid=row_id, values=values, tags=("highlight_whois", "highlight_broscan", "highlight_virustotal", "highlight_abuseipdb"))



    def update_checkboxes(self):
        """Checkbox durumlarını günceller"""
        if self.all_events_var.get():
            self.suspicious_var.set(False)
            self.only_malicious_var.set(False)
        elif self.suspicious_var.get():
            self.all_events_var.set(False)
            self.only_malicious_var.set(False)
        elif self.only_malicious_var.get():
            self.all_events_var.set(False)
            self.suspicious_var.set(False)


    
    def send_alert(self, conn, ip_status, abuseipdb_status, country, cloudflare_status):
        """Yeni əlaqə haqqında bildiriş göndərmək"""

        ip = conn.raddr.ip
        port = conn.raddr.port

        # Proses adını alırıq
        if conn.pid:
            try:
                process_name = psutil.Process(conn.pid).name()
            except psutil.NoSuchProcess:
                process_name = 'Unknown'
        else:
            process_name = 'Unknown'

        # Checkbox durumuna görə filtr
        if self.only_malicious_var.get():  # "Only Malicious" seçilibsə
            if "Malicious" not in ip_status:
                return  # Əgər nəticələr "Malicious" deyilsə, bildiriş göndərməyin
        elif self.suspicious_var.get():  # "Only Suspicious and Malicious" seçilibsə
            if not ("Malicious" in ip_status or "Suspicious" in ip_status):
                return  # Əgər nəticələr "Malicious" və ya "Suspicious" deyilsə, bildiriş göndərməyin

        # Emoji əsaslı alert statusu
        if "Malicious" in ip_status:
            event_type_emoji = "💥 Malicious"
            sound_type = "malicious"
        elif "Suspicious" in ip_status:
            event_type_emoji = "⚠️ Suspicious"
            sound_type = "warning"
        elif "Clean" in ip_status:
            event_type_emoji = "✅ Clean"
            sound_type = None
        else:
            event_type_emoji = "🔍 Checking"
            sound_type = None

        # Emoji əsaslı bildiriş məzmunu
        cloudflare_emoji = "☁️" if cloudflare_status == "Yes" else "🚫"
        abuse_emoji = "🔥" if "High Risk" in abuseipdb_status else "⚖️" if "Medium Risk" in abuseipdb_status else "🔒"
        virustotal_emoji = "💀" if "Malicious" in ip_status else "⚠️" if "Suspicious" in ip_status else "✅"

        # Notification mesajı (Windows üçün)
        notification_message = (
            f"🌐 IP: {ip}:{port} | 💻 Process: {process_name}\n"
            f"🌏 Country: {country} | {cloudflare_emoji} Cloudflare: {cloudflare_status}\n"
            f"{virustotal_emoji} Virustotal: {ip_status}\n"
            f"{abuse_emoji} AbuseIPDB: {abuseipdb_status}\n"
            "👁️ Big Bro says: Monitor your network carefully!"
        )

        # Telegram mesajı (istədiyiniz formatda)
        telegram_message = (
            f"{event_type_emoji}\n"
            f"🌐 IP: {ip}:{port}\n"
            f"💻 Process: {process_name}\n"
            f"🌏 Country: {country}\n"
            f"{cloudflare_emoji} Cloudflare: {cloudflare_status}\n"
            f"{virustotal_emoji} Virustotal: {ip_status}\n"
            f"{abuse_emoji} AbuseIPDB: {abuseipdb_status}\n"
            "👁️ Big Brother is watching you!"
        )

        notification_title = f"Event: {event_type_emoji}"

        # Windows bildirişi göstəririk
        send_notification(notification_title, notification_message)

        # Telegram mesajını göndəririk (artıq asinxron şəkildə işləyəcək)
        self.send_telegram_alert(telegram_message)

        # Riskli vəziyyətlər üçün səs siqnalı çalırıq
        if sound_type == "malicious":
            winsound.MessageBeep(winsound.MB_ICONHAND)  # Malicious üçün kritik səs
        elif sound_type == "warning":
            winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)







    

    def kill_connection(self):
        selected_item = self.tree.selection()
        if selected_item:
            values = self.tree.item(selected_item[0], 'values')
            ip = values[0]
            port = int(values[1])  # Corrected index for Port

            answer = messagebox.askyesno("Confirm Kill", f"Are you sure you want to kill the connection to {ip}:{port}?")
            if not answer:
                return

            connection_tuple = (ip, port)
            if connection_tuple in process_info:
                process_name, conn = process_info[connection_tuple]
                try:
                    process = psutil.Process(conn.pid)
                    process.terminate()
                    self.status_label.config(text=f"Process for {ip}:{port} Terminated")
                    notification.notify(
                        title="Connection Terminated",
                        message=f"Process for IP {ip}:{port} was terminated.",
                        timeout=5
                    )
                    messagebox.showinfo("Connection Terminated", f"Process for IP {ip}:{port} was successfully terminated.")
                except Exception as e:
                    self.status_label.config(text="Failed to terminate connection")
                    messagebox.showerror("Error", f"Failed to terminate connection for {ip}:{port}.\nError: {e}")
            else:
                self.status_label.config(text="No process found for selected IP and Port")
                messagebox.showerror("Error", "No process found for the selected IP and Port")

    def block_ip(self):
        """Block the selected IP."""
        selected_item = self.tree.selection()
        if selected_item:
            values = self.tree.item(selected_item[0], 'values')
            ip = values[0]

            answer = messagebox.askyesno("Confirm Block", f"Are you sure you want to block the IP {ip}?")
            
            if answer:
                os.system(f'netsh advfirewall firewall add rule name="Block {ip}" dir=in action=block remoteip={ip}')
                self.status_label.config(text=f"{ip} has been blocked.")
                notification.notify(
                    title="IP Blocked",
                    message=f"{ip} has been blocked.",
                    timeout=5
                )
                messagebox.showinfo("IP Blocked", f"The IP {ip} has been successfully blocked.")
            else:
                # User selected "No" or closed the dialog with "X"
                self.status_label.config(text="Block IP operation canceled.")


# GUI-yə başlamaq
if __name__ == "__main__":
    global main_window
    main_window = tk.Tk()
    selector = NetworkCardSelector(main_window)
    main_window.mainloop()
