class Flag:
    def __init__(self, packets=None):
        self.psh_flag_cnt = 0
        self.urg_flag_cnt = 0
        self.fin_flag_cnt = 0
        self.syn_flag_cnt = 0
        self.rst_flag_cnt = 0
        self.push_flag_cnt = 0 
        self.ack_flag_cnt = 0
        self.cwe_flag_cnt = 0
        self.ece_flag_cnt = 0

        self.packets = packets if packets else []

    def update(self, packets):
        """Update packet list reference"""
        self.packets = packets

    def add_packet_incremental(self, packet):
        """Incrementally update flag counts with new packet"""
        if not hasattr(packet, "tcp"):
            return

        tcp = packet.tcp

        if getattr(tcp, "flags_fin", "0") == "1":
            self.fin_flag_cnt += 1

        if getattr(tcp, "flags_syn", "0") == "1":
            self.syn_flag_cnt += 1

        if getattr(tcp, "flags_rst", "0") == "1":
            self.rst_flag_cnt += 1

        if getattr(tcp, "flags_push", "0") == "1":
            self.psh_flag_cnt += 1
            self.push_flag_cnt += 1

        if getattr(tcp, "flags_ack", "0") == "1":
            self.ack_flag_cnt += 1

        if getattr(tcp, "flags_urg", "0") == "1":
            self.urg_flag_cnt += 1

        if getattr(tcp, "flags_cwr", "0") == "1":
            self.cwe_flag_cnt += 1

        if getattr(tcp, "flags_ecn", "0") == "1":
            self.ece_flag_cnt += 1

    def calculate(self):
        """Full recalculation (fallback for compatibility)"""
        self.psh_flag_cnt = 0
        self.urg_flag_cnt = 0
        self.fin_flag_cnt = 0
        self.syn_flag_cnt = 0
        self.rst_flag_cnt = 0
        self.push_flag_cnt = 0
        self.ack_flag_cnt = 0
        self.cwe_flag_cnt = 0
        self.ece_flag_cnt = 0

        for pkt in self.packets:
            packet = pkt

            if not hasattr(packet, "tcp"):
                continue

            tcp = packet.tcp

            if getattr(tcp, "flags_fin", "0") == "1":
                self.fin_flag_cnt += 1

            if getattr(tcp, "flags_syn", "0") == "1":
                self.syn_flag_cnt += 1

            if getattr(tcp, "flags_rst", "0") == "1":
                self.rst_flag_cnt += 1

            if getattr(tcp, "flags_push", "0") == "1":
                self.psh_flag_cnt += 1
                self.push_flag_cnt += 1

            if getattr(tcp, "flags_ack", "0") == "1":
                self.ack_flag_cnt += 1

            if getattr(tcp, "flags_urg", "0") == "1":
                self.urg_flag_cnt += 1

            if getattr(tcp, "flags_cwr", "0") == "1":
                self.cwe_flag_cnt += 1

            if getattr(tcp, "flags_ecn", "0") == "1":
                self.ece_flag_cnt += 1
