from src.flow import Flow

class FlowSession:
    def __init__(self, idle_timeout, active_timeout, label):
        self.idle_timeout = idle_timeout
        self.active_timeout = active_timeout
        self.label = label

        self.active_flow = []
        self.inactive_flow = []

    def _invalidate_flow(self, packet):
        for flow in self.active_flow:
            if float(packet.sniff_timestamp) - flow.end_time > self.idle_timeout:
                self.inactive_flow.append(flow)
                self.active_flow.remove(flow)
                continue
            if float(packet.sniff_timestamp) - flow.start_time > self.active_timeout:
                self.inactive_flow.append(flow)
                self.active_flow.remove(flow)
                continue

        return self.inactive_flow

    def _get_packet_flow(self, packet):
        for flow in self.active_flow:
            if flow.src_ip == packet.ip.src and flow.dst_ip == packet.ip.dst:
                return flow
        return None

    def process_packet(self, packet):
        self._invalidate_flow(packet)
        flow = self._get_packet_flow(packet)
        
        if flow:
            flow.update_flow(packet)
        else:
            new_flow = Flow(packet, self.active_timeout, self.idle_timeout, self.label)
            self.active_flow.append(new_flow)

    def _close_all_flow(self):
        for flow in self.active_flow:
            self.inactive_flow.append(flow)
        self.active_flow = []

    def get_all_flow(self):
        return self.inactive_flow
    
    
    
