from scapy.all import sniff, IP, TCP, UDP, DNS, Raw
import tkinter as tk
from tkinter import ttk, messagebox, Toplevel
from tkinter.scrolledtext import ScrolledText
import threading
from datetime import datetime
import pytz  # GMT vaxt zonaları üçün
import psutil


class NetworkMonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Traffic Monitor")
        self.running = False
        self.all_rows = []  # Əsas məlumatları saxlayırıq
        self.all_packets = []  # Saxlanan bütün paketlər
        self.filters_applied = False  # Filtrlərin aktiv olub olmadığını yoxlayırıq

        # Şəbəkə interfeysi seçmək üçün
        self.interface_label = tk.Label(root, text="Select Network Interface:")
        self.interface_label.pack(pady=5)

        self.interface_combo = ttk.Combobox(root, values=self.get_interfaces(), state="readonly")
        self.interface_combo.pack(pady=5)

        # GMT seçimi üçün
        self.gmt_frame = tk.Frame(root)
        self.gmt_frame.pack(pady=5)

        tk.Label(self.gmt_frame, text="Select GMT Timezone:").grid(row=0, column=0, padx=5)
        self.gmt_combo = ttk.Combobox(self.gmt_frame, values=self.get_gmt_list(), state="readonly", width=30)
        self.gmt_combo.grid(row=0, column=1, padx=5)
        self.gmt_combo.set("Default (UTC)")  # Default olaraq UTC seçilir

        # Filtrlər üçün input sahələri
        self.filter_frame = tk.Frame(root)
        self.filter_frame.pack(pady=5)

        tk.Label(self.filter_frame, text="IP Filter:").grid(row=0, column=0, padx=5)
        self.ip_filter = tk.Entry(self.filter_frame)
        self.ip_filter.grid(row=0, column=1, padx=5)

        tk.Label(self.filter_frame, text="Port Filter:").grid(row=0, column=2, padx=5)
        self.port_filter = tk.Entry(self.filter_frame)
        self.port_filter.grid(row=0, column=3, padx=5)

        tk.Label(self.filter_frame, text="Protocol Filter:").grid(row=0, column=4, padx=5)
        self.protocol_filter = ttk.Combobox(self.filter_frame, values=["Any", "TCP", "UDP", "DNS", "mDNS", "HTTP"], state="readonly")

        self.protocol_filter.grid(row=0, column=5, padx=5)
        self.protocol_filter.current(0)

        # Filtr düymələri
        self.filter_button_frame = tk.Frame(root)
        self.filter_button_frame.pack(pady=5)

        self.search_button = tk.Button(self.filter_button_frame, text="Apply Filters", command=self.apply_filters, bg="#007BFF", fg="white")
        self.search_button.pack(side="left", padx=5)

        self.clear_button = tk.Button(self.filter_button_frame, text="Clear Filters", command=self.clear_filters, bg="#FF5733", fg="white")
        self.clear_button.pack(side="left", padx=5)

        # Başlat/Durdur düymələri
        self.start_button = tk.Button(root, text="Start Monitoring", command=self.start_monitoring, bg="green", fg="white")
        self.start_button.pack(pady=5)

        self.stop_button = tk.Button(root, text="Stop Monitoring", command=self.stop_monitoring, bg="red", fg="white", state="disabled")
        self.stop_button.pack(pady=5)

        # Cədvəl yaratmaq
        self.tree = ttk.Treeview(root, columns=("Time", "Source", "Destination", "Protocol", "Port", "Details"), show="headings")
        self.tree.heading("Time", text="Time")
        self.tree.heading("Source", text="Source")
        self.tree.heading("Destination", text="Destination")
        self.tree.heading("Protocol", text="Protocol")
        self.tree.heading("Port", text="Port")
        self.tree.heading("Details", text="Details")

        self.tree.column("Time", width=200)
        self.tree.column("Source", width=150)
        self.tree.column("Destination", width=150)
        self.tree.column("Protocol", width=100)
        self.tree.column("Port", width=100)
        self.tree.column("Details", width=300)

        self.tree.pack(fill="both", expand=True)

        # Sağ klik menyusu
        self.tree.bind("<Button-3>", self.show_context_menu)

        # Scrollbar
        self.scrollbar = ttk.Scrollbar(root, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=self.scrollbar.set)
        self.scrollbar.pack(side="right", fill="y")

    def get_interfaces(self):
        """Mövcud şəbəkə interfeyslərini əldə edir."""
        return list(psutil.net_if_addrs().keys())

    def get_gmt_list(self):
        """Mövcud GMT zaman zonalarını əldə edir."""
        return ["Default (UTC)"] + [f"GMT{offset:+d}" for offset in range(-12, 13)]

    def start_monitoring(self):
        """Monitorinqi başlat."""
        interface = self.interface_combo.get()
        if not interface:
            messagebox.showerror("Error", "Please select a network interface.")
            return

        self.running = True
        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")

        self.all_rows.clear()
        self.all_packets.clear()
        self.tree.delete(*self.tree.get_children())  # Cədvəli təmizləyin

        threading.Thread(target=self.sniff_packets, args=(interface,), daemon=True).start()

    def stop_monitoring(self):
        """Monitorinqi dayandır."""
        self.running = False
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")

    def sniff_packets(self, interface):
        """Paketləri dinləyir və GUI-də göstərir."""
        def process_packet(packet):
            if not self.running:
                return False

            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                protocol = self.identify_protocol(packet)
                port = self.extract_port(packet)
                details = self.extract_details(packet)
                timestamp = self.convert_time(packet.time)

                row = (timestamp, src_ip, dst_ip, protocol, port, details)

                if self.filters_applied:
                    if not self.row_matches_filters(row):
                        return

                self.all_rows.append(row)
                self.all_packets.append(packet)
                self.tree.insert("", "end", values=row)

        sniff(iface=interface, prn=process_packet, store=False)

    def identify_protocol(self, packet):
        """Paketin protokolunu müəyyənləşdirir."""
        if TCP in packet:
            if Raw in packet and self.is_http_packet(packet):
                return "HTTP"
            return "TCP"
        elif UDP in packet:
            return "UDP"
        elif DNS in packet:
            return "DNS"
        elif "224.0.0.251" in [packet[IP].dst, packet[IP].src]:
            return "mDNS"
        return "Other"


    def extract_port(self, packet):
        """Paketdən port məlumatını çıxarır."""
        if TCP in packet:
            return packet[TCP].sport
        elif UDP in packet:
            return packet[UDP].sport
        return "N/A"

    def extract_details(self, packet):
        """Paketdən əlavə məlumatı çıxarır."""
        if DNS in packet and packet[DNS].qd:
            return f"DNS Query: {packet[DNS].qd.qname.decode()}"
        if Raw in packet:
            return f"Raw Data: {packet[Raw].load[:30]}"
        return "Right click To go Details"



    def convert_time(self, timestamp):
        """Paketin vaxtını seçilmiş GMT-ə çevirir."""
        gmt_selection = self.gmt_combo.get()
        if gmt_selection == "Default (UTC)":
            return datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
        else:
            offset = int(gmt_selection.replace("GMT", ""))
            target_timezone = pytz.timezone(f"Etc/GMT{offset:+d}")
            return datetime.fromtimestamp(timestamp, target_timezone).strftime('%Y-%m-%d %H:%M:%S')

    def apply_filters(self):
        """Filterləri tətbiq et."""
        self.filters_applied = True
        self.tree.delete(*self.tree.get_children())  # Mövcud məlumatları sil

        for row in self.all_rows:
            if self.row_matches_filters(row):
                self.tree.insert("", "end", values=row)

    def clear_filters(self):
        """Filterləri təmizlə."""
        self.filters_applied = False
        self.ip_filter.delete(0, tk.END)
        self.port_filter.delete(0, tk.END)
        self.protocol_filter.current(0)

        self.tree.delete(*self.tree.get_children())
        for row in self.all_rows:
            self.tree.insert("", "end", values=row)

    def row_matches_filters(self, row):
        """Cədvəl sətirinin filterlərə uyğun olub-olmadığını yoxla."""
        ip_filter = self.ip_filter.get().strip()
        port_filter = self.port_filter.get().strip()
        protocol_filter = self.protocol_filter.get()

        time, src_ip, dst_ip, protocol, port, details = row

        if ip_filter and ip_filter not in (src_ip, dst_ip):
            return False
        if port_filter and str(port_filter) != str(port):
            return False
        if protocol_filter != "Any" and protocol_filter != protocol:
            return False

        return True

    def show_context_menu(self, event):
        """Sağ klik menyusu."""
        row_id = self.tree.identify_row(event.y)
        if row_id:
            menu = tk.Menu(self.root, tearoff=0)
            menu.add_command(label="View Details", command=lambda: self.show_packet_details(row_id))
            menu.add_command(label="Go to Raw", command=lambda: self.show_raw_data(row_id))
            menu.post(event.x_root, event.y_root)


    def show_packet_details(self, row_id):
        """Seçilmiş paket haqqında ətraflı məlumat göstərir."""
        packet_index = int(self.tree.index(row_id))
        packet = self.all_packets[packet_index]

        detail_window = Toplevel(self.root)
        detail_window.title("Packet Details")
        detail_window.geometry("700x500")

        text = ScrolledText(detail_window, wrap="word", font=("Courier", 10))

        # Paket detalları
        packet_details = packet.show(dump=True)

        # Raw Data çıxarılır
        raw_data = "No Raw Data Found."
        if Raw in packet:
            try:
                raw_data = packet[Raw].load.decode("utf-8", errors="ignore")  # UTF-8 ilə dekod edilir
            except UnicodeDecodeError:
                raw_data = repr(packet[Raw].load)  # Əgər dekod edilməzsə, binar məlumatı göstər

        # Tam detalları birləşdir
        full_details = f"### Packet Details ###\n{packet_details}\n\n### Raw Data ###\n{raw_data}"
        
        # GUI-də göstər
        text.insert("1.0", full_details)
        text.config(state="disabled")  # Mətn dəyişdirilə bilməz
        text.pack(fill="both", expand=True)

        close_button = tk.Button(detail_window, text="Close", command=detail_window.destroy)
        close_button.pack(pady=5)






    def is_http_packet(self, packet):
        """HTTP paketlərini müəyyən edir."""
        if Raw in packet:
            try:
                payload = packet[Raw].load.decode(errors="ignore")
                return payload.startswith(("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "HTTP"))
            except:
                return False
        return False


    def analyze_http_payload(self, payload):
        """HTTP yüklərini analiz edir."""
        try:
            payload = payload.decode(errors="ignore")
            headers, body = "", ""
            if "\r\n\r\n" in payload:
                headers, body = payload.split("\r\n\r\n", 1)
            header_lines = headers.split("\r\n")
            request_line = header_lines[0] if header_lines else ""
            
            # URI-ni çıxarır (GET və POST üçün)
            uri = request_line.split(" ")[1] if len(request_line.split(" ")) > 1 else ""

            # Form məlumatlarını yoxlayır (POST üçün)
            form_data = ""
            if "Content-Type: application/x-www-form-urlencoded" in headers:
                form_data = f"Form Data: {body.strip()}"

            # Əsas detallar
            return f"URI: {uri}\n{form_data}\nHeaders:\n{headers}"
        except:
            return "Malformed HTTP Packet"



    def show_raw_data(self, row_id):
        """Seçilmiş paketdəki Raw Data-nı tam şəkildə göstərir."""
        packet_index = int(self.tree.index(row_id))
        packet = self.all_packets[packet_index]  # Tam paketi əldə et

        detail_window = Toplevel(self.root)
        detail_window.title("Raw Data Viewer")
        detail_window.geometry("700x500")

        text = ScrolledText(detail_window, wrap="word", font=("Courier", 10))

        # Raw Data çıxarılır
        raw_data = "No Raw Data Found."  # Default olaraq
        if Raw in packet:  # Əgər Raw varsa
            try:
                raw_data = packet[Raw].load.decode("utf-8", errors="ignore")  # UTF-8 ilə dekod et
            except UnicodeDecodeError:
                raw_data = repr(packet[Raw].load)  # Əgər UTF-8 uyğun olmazsa, binar məlumatı göstər

        # GUI-də göstər
        text.insert("1.0", f"### Raw Data ###\n{raw_data}")
        text.config(state="disabled")  # Mətn dəyişdirilə bilməz
        text.pack(fill="both", expand=True)

        close_button = tk.Button(detail_window, text="Close", command=detail_window.destroy)
        close_button.pack(pady=5)





if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkMonitorApp(root)
    root.mainloop()