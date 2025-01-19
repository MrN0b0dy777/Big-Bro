import asyncio
import tkinter as tk
from tkinter import messagebox
import socket
from threading import Thread


class PortScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Optimized Port Scanner")

        # GUI ölçüləri
        self.root.geometry("500x500")
        self.root.configure(bg="#2e2e2e")

        # Başlıq etiketi
        self.label = tk.Label(self.root, text="IP və ya URL daxil edin:", font=("Arial", 12), bg="#2e2e2e", fg="#ffffff")
        self.label.pack(pady=10)

        # IP və ya URL daxil etmək üçün entry
        self.entry = tk.Entry(self.root, font=("Arial", 12), width=40, bg="#424242", fg="#ffffff", insertbackground="#ffffff")
        self.entry.pack(pady=10)

        # Skan düymələrinin yerləşəcəyi frame
        button_frame = tk.Frame(self.root, bg="#2e2e2e")
        button_frame.pack(pady=10)

        # 1-1024 port aralığı düyməsi
        self.scan_1024_button = tk.Button(button_frame, text="Scan 1-1024", font=("Arial", 12), bg="#016c87", fg="#ffffff", command=self.scan_1024_ports)
        self.scan_1024_button.pack(side="left", padx=5)

        # 1-65535 port aralığı düyməsi
        self.scan_65535_button = tk.Button(button_frame, text="Scan 1-65535", font=("Arial", 12), bg="#016c87", fg="#ffffff", command=self.scan_65535_ports)
        self.scan_65535_button.pack(side="left", padx=5)

        # Nəticə göstərmək üçün text sahəsi
        self.result_text = tk.Text(self.root, font=("Courier", 10), bg="#424242", fg="#ffffff", wrap="word", height=20)
        self.result_text.pack(pady=10)

        # Pəncərəni bağlama düyməsi
        self.close_button = tk.Button(self.root, text="Close", font=("Arial", 12), bg="#830000", fg="#ffffff", command=self.root.destroy)
        self.close_button.pack(pady=10)

    async def scan_port(self, target, port):
        """
        Asinxron port skaneri.
        """
        try:
            reader, writer = await asyncio.open_connection(target, port)
            try:
                service = socket.getservbyport(port, "tcp")
            except OSError:
                service = "Unknown"
            self.result_text.insert("end", f"Port {port}: OPEN ({service})\n")
            self.result_text.see("end")
            writer.close()
            await writer.wait_closed()
        except:
            pass

    async def scan_ports_async(self, target, ports):
        """
        Verilmiş portlar siyahısını asinxron skan edir.
        """
        self.result_text.insert("end", "Scanning in progress...\n")
        self.result_text.see("end")
        tasks = [self.scan_port(target, port) for port in ports]
        await asyncio.gather(*tasks)
        self.result_text.insert("end", "Scanning completed.\n")
        self.result_text.see("end")

    def resolve_target(self):
        """Daxil edilən hədəfi (IP və ya URL) həll edir."""
        target = self.entry.get().strip()
        if target.startswith("http://") or target.startswith("https://"):
            target = target.split("://")[1].split("/")[0]

        try:
            ip = socket.gethostbyname(target)
            return ip
        except socket.gaierror:
            messagebox.showerror("Error", "Invalid IP or URL.")
            return None

    def start_async_scan(self, ports):
        """Asinxron skanı işə salır."""
        target = self.resolve_target()
        if target:
            self.result_text.delete("1.0", "end")
            self.result_text.insert("1.0", f"Scanning started for {target}...\n")

            # Asinxron skan prosesi fon işçisi olaraq işə düşür
            def run_scan():
                asyncio.run(self.scan_ports_async(target, ports))

            Thread(target=run_scan, daemon=True).start()

    def scan_1024_ports(self):
        """1-1024 portlarını skan edir."""
        self.start_async_scan(range(1, 1025))

    def scan_65535_ports(self):
        """1-65535 portlarını skan edir."""
        self.start_async_scan(range(1, 65536))


# GUI tətbiqini işə salırıq
if __name__ == "__main__":
    root = tk.Tk()
    app = PortScannerApp(root)
    root.mainloop()
