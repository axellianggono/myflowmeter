from src.packet_size import PacketSize
from src.iat import IAT
from src.flag import Flag
from src.header import Header

class Flow:
    def __init__(self, packet):
        self.packets = [(packet, "FWD")]
        
        self.src_ip = packet.ip.src
        self.dst_ip = packet.ip.dst
        self.src_port = packet[packet.transport_layer].srcport
        self.dst_port = packet[packet.transport_layer].dstport
        self.protocol = packet.transport_layer
        self.start_time = float(packet.sniff_timestamp)
        self.end_time = float(packet.sniff_timestamp)
        
        self.flow_duration = self.start_time - self.end_time
        self.total_fwd_packets = 1
        self.total_bwd_packets = 0

        self.flow_packet_size = PacketSize(self._get_all_packets())
        self.fw_packet_size = PacketSize(self._get_forward_packets())
        self.bw_packet_size = PacketSize(self._get_backward_packets())

        self.flow_byte_per_sec = 0
        self.flow_packet_per_sec = 0

        self.flow_iat = IAT(self._get_all_packets())
        self.fw_iat = IAT(self._get_forward_packets())
        self.bw_iat = IAT(self._get_backward_packets())

        self.flags = Flag(self._get_all_packets())

        self.fw_header = Header(self._get_all_packets())
        self.bw_header = Header(self._get_all_packets())

        self.forward_packet_per_sec = 0
        self.backward_packet_per_sec = 0
        self.down_up_ratio = 0

        self.fw_seg_avg = 0
        self.bw_seg_avg = 0

    def _get_all_packets(self):
        return [packet[0] for packet in self.packets]

    def _get_forward_packets(self):
        return [packet[0] for packet in self.packets if packet[1] == "FWD"]

    def _get_backward_packets(self):
        return [packet[0] for packet in self.packets if packet[1] == "BWD"]   
    
    def update_flow(self, packet):
        self.end_time = float(packet.sniff_timestamp)
        self.flow_duration = self.end_time - self.start_time

        if packet.ip.src == self.src_ip and packet.ip.dst == self.dst_ip:
            self.total_fwd_packets += 1
            self.packets.append((packet, "FWD"))
        else:
            self.total_bwd_packets += 1
            self.packets.append((packet, "BWD"))

    def get_feature(self):
        self.fw_packet_size.update_packets(self._get_forward_packets())
        self.bw_packet_size.update_packets(self._get_backward_packets())
        self.flow_iat.update_packets(self._get_all_packets())
        self.fw_iat.update_packets(self._get_forward_packets())
        self.bw_iat.update_packets(self._get_backward_packets())
        self.flags.update(self._get_all_packets())
        self.fw_header.update(self._get_forward_packets())
        self.bw_header.update(self._get_backward_packets())
        self.flow_packet_size.update_packets(self._get_all_packets())

        self.fw_packet_size.calculate()
        self.bw_packet_size.calculate()
        self.flow_iat.calculate()
        self.fw_iat.calculate()
        self.bw_iat.calculate()
        self.flags.calculate()
        self.fw_header.calculate()
        self.bw_header.calculate()
        self.flow_packet_size.calculate()

        self.flow_duration = self.end_time - self.start_time

        if self.flow_duration != 0:
            self.flow_byte_per_sec = self.fw_packet_size.total_size_pkt / self.flow_duration
            self.flow_packet_per_sec = self.total_fwd_packets / self.flow_duration
            self.forward_packet_per_sec = self.total_fwd_packets / self.flow_duration
            self.backward_packet_per_sec = self.total_bwd_packets / self.flow_duration
            self.down_up_ratio = self.total_bwd_packets / self.total_fwd_packets
        
        self.fw_seg_avg = self.fw_packet_size.total_size_pkt / self.total_fwd_packets if self.total_fwd_packets != 0 else 0

        self.bw_seg_avg = self.bw_packet_size.total_size_pkt / self.total_bwd_packets if self.total_bwd_packets != 0 else 0

        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "flow_duration": self.flow_duration,
            "total_fwd_packets": self.total_fwd_packets,
            "total_bwd_packets": self.total_bwd_packets,
            "fw_packet_size": self.fw_packet_size.total_size_pkt,
            "fw_packet_size_max": self.fw_packet_size.max_size_pkt,
            "fw_packet_size_min": self.fw_packet_size.min_size_pkt,
            "fw_packet_size_avg": self.fw_packet_size.avg_size_pkt,
            "fw_packet_size_std": self.fw_packet_size.std_size_pkt,
            "bw_packet_size": self.bw_packet_size.total_size_pkt,
            "bw_packet_size_max": self.bw_packet_size.max_size_pkt,
            "bw_packet_size_min": self.bw_packet_size.min_size_pkt,
            "bw_packet_size_avg": self.bw_packet_size.avg_size_pkt,
            "bw_packet_size_std": self.bw_packet_size.std_size_pkt,
            "flow_byte_per_sec": self.flow_byte_per_sec,
            "flow_packet_per_sec": self.flow_packet_per_sec,
            "flow_iat_avg": self.flow_iat.avg,
            "flow_iat_std": self.flow_iat.std,
            "flow_iat_max": self.flow_iat.max,
            "flow_iat_min": self.flow_iat.min,
            "fw_iat_total": self.fw_iat.total_time,
            "fw_iat_avg": self.fw_iat.avg,
            "fw_iat_std": self.fw_iat.std,
            "fw_iat_max": self.fw_iat.max,
            "fw_iat_min": self.fw_iat.min,
            "bw_iat_total": self.bw_iat.total_time,
            "bw_iat_avg": self.bw_iat.avg,
            "bw_iat_std": self.bw_iat.std,
            "bw_iat_max": self.bw_iat.max,
            "bw_iat_min": self.bw_iat.min,
            "fw_psh_flag": self.flags.psh_flag_cnt,
            "bw_psh_flag": self.flags.psh_flag_cnt,
            "fw_urg_flag": self.flags.urg_flag_cnt,
            "bw_urg_flag": self.flags.urg_flag_cnt,
            "fw_hdr_len": self.fw_header.total_hdr_len,
            "bw_hdr_len": self.bw_header.total_hdr_len,
            "fw_pkt_s": self.forward_packet_per_sec,
            "bw_pkt_s": self.backward_packet_per_sec,
            "pkt_len_min": self.flow_packet_size.min_size_pkt,
            "pkt_len_max": self.flow_packet_size.max_size_pkt,
            "pkt_len_avg": self.flow_packet_size.avg_size_pkt,
            "pkt_len_std": self.flow_packet_size.std_size_pkt,
            "pkt_len_va": self.flow_iat.min,
            "fin_cnt": self.flags.fin_flag_cnt,
            "syn_cnt": self.flags.syn_flag_cnt,
            "rst_cnt": self.flags.rst_flag_cnt,
            "push_cnt": self.flags.push_flag_cnt,
            "ack_cnt": self.flags.ack_flag_cnt,
            "urg_cnt": self.flags.urg_flag_cnt,
            "cwe_cnt": self.flags.cwe_flag_cnt,
            "ece_cnt": self.flags.ece_flag_cnt,
            "down_up_ratio": self.down_up_ratio,
            "pkt_size_avr": self.flow_packet_size.avg_size_pkt,
            "fw_seg_avg": self.fw_seg_avg,
            "bw_seg_avg": self.bw_seg_avg
        }