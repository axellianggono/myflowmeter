import pyshark
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

    def write_to_file(self, filename):
        flows = self.flow_session.get_all_flow()

        with open(filename, "w") as f:
            for flow in flows:
                f.write(str(flow.get_feature()) + "\n")
            
        print(f"[*] Saved to {filename}")

