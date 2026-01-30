import pyshark
from pyshark.capture.live_capture import UnknownInterfaceException
from src.flow_session import FlowSession

class Extract:
    def __init__(self, idle_time, active_time, label):
        self.idle_time = idle_time
        self.active_time = active_time

        self.flow_session = FlowSession(idle_time, active_time, label)

    def process_file(self, filename):
        with pyshark.FileCapture(filename) as capture:
            for packet in capture:
                if "IP" not in packet:
                    continue
                self.flow_session.process_packet(packet)
            
        print(f"[*] Finished Processing {filename}")
    
    def _get_available_interfaces(self):
        """Mengambil daftar interface yang tersedia melalui tshark."""
        try:
            # Mengembalikan list nama interface
            return pyshark.tshark.tshark.get_tshark_interfaces()
        except Exception as e:
            print(f"[-] Gagal mendapatkan interface: {e}")
            return []

    def process_live(self, interface, filename):
        with open(filename, "w") as f:
            capture = pyshark.LiveCapture(interface=interface)
            
            try:
                print(f"[*] Menghubungkan ke interface: {interface}...")
                
                for packet in capture.sniff_continuously():
                    if "IP" not in packet:
                        continue
                    
                    invalidated_flow = self.flow_session.process_packet(packet)
                    for flow in invalidated_flow:
                        f.write(str(flow.get_feature()) + "\n")
                        f.flush()

            except UnknownInterfaceException:
                print(f"\n[-] Error: Interface '{interface}' tidak ditemukan!")
                print("[*] Silahkan pilih salah satu interface berikut:")
                
                interfaces = self._get_available_interfaces()
                for i, iface in enumerate(interfaces):
                    print(f"    {i+1}. {iface}")
                
                return
            
            except KeyboardInterrupt:
                print("\n[*] Stopping capture...")
                self.flow_session._close_all_flow()
                for flow in self.flow_session.get_all_flow():
                    f.write(str(flow.get_feature()) + "\n")


    def write_to_file(self, filename):
        flows = self.flow_session.get_all_flow()

        with open(filename, "w") as f:
            for flow in flows:
                f.write(str(flow.get_feature()) + "\n")
            
        print(f"[*] Saved to {filename}")

