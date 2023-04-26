from flow import Flow

class Node:
    """Node in a Network"""
    def __init__(self, mac_addr):
        self.mac_addr = mac_addr
        self.name = None
        self.ip_addrs = []
        self.is_active = None
        self.input_flows = []
        self.output_flows = []
        self.last_input_pkt_time = 0
        self.last_output_pkt_time = 0
        self.uplink_total = 0
        self.downlink_total = 0
    
    def set_input_flow(self, flow):
        """Appends flow object reference to input flows list"""
        self.input_flows.append(flow)
        # flow.dst_node = self.mac_addr

    def set_output_flow(self, flow):
        """Appends flow object reference to output flows list"""
        self.output_flows.append(flow)
        # flow.src_node = self.mac_addr
    
    def check_ip_addr(self, ip_addr):
        if ip_addr not in self.ip_addrs:
            self.ip_addrs.append(ip_addr)
    

    def get_throughput(self):


        def compute_relative_throughput(flow, start_time, data_struct):
            for pkt in flow.traffic:
                time_interval_key = int((pkt['relative_timestamp'] - start_time) // sampling_rate) * sampling_rate
                data_struct[time_interval_key]['pkt_rate'] += 1
                data_struct[time_interval_key]['byte_rate'] += pkt['payload_size']
        
        def compute_throughput(flow, start_time, pkt_rate_struct, byte_rate_struct):
            for pkt in flow.traffic:
                index = int((pkt['relative_timestamp'] - start_time) // sampling_rate)
                pkt_rate_struct[index] += 1
                byte_rate_struct[index] += pkt['payload_size']
        

        def _find_last_pkt_time(flows):
            res = 0
            for flow in flows:
                res = max(flow.traffic[-1]['relative_timestamp'], res)
            return res

        input_start_time = self.input_flows[0].traffic[0]['relative_timestamp']
        input_duration = int(_find_last_pkt_time(self.input_flows) - input_start_time)
        output_start_time = self.output_flows[0].traffic[0]['relative_timestamp']
        output_duration = int(_find_last_pkt_time(self.output_flows) - output_start_time)
        sampling_rate = 30
        # input_throughput = {i: {'pkt_rate': 0, 'byte_rate': 0} for i in range(0, input_duration + sampling_rate, sampling_rate)}
        # output_throughput = {i: {'pkt_rate': 0, 'byte_rate': 0} for i in range(0, output_duration + sampling_rate, sampling_rate)}
        input_pkt_rate = [0] * input_duration
        input_byte_rate = [0] * input_duration
        output_pkt_rate = [0] * output_duration
        output_byte_rate = [0] * output_duration

        for flow in self.input_flows:
            # compute_relative_throughput(flow, input_start_time, input_throughput)
            compute_throughput(flow, input_start_time, input_pkt_rate, input_byte_rate)
            
        for flow in self.output_flows:
            # compute_relative_throughput(flow, output_start_time, output_throughput)
            compute_throughput(flow, output_start_time, output_pkt_rate, output_byte_rate)

        input_x_time = [i for i in range(0, input_duration + sampling_rate, sampling_rate)]
        output_x_time = [i for i in range(0, output_duration + sampling_rate, sampling_rate)]
        
        response_obj = {
            'input_time': input_x_time,
            'input_pkt_rate': input_pkt_rate,
            'input_byte_rate': input_byte_rate,
            'output_time': output_x_time,
            'output_pkt_rate': output_pkt_rate,
            'output_byte_rate': output_byte_rate
        }

        return response_obj

    
    
    # def get_flows(self, device_flow_table):
    #     flow_table = {}
    #     for direction in device_flow_table:
    #         for flow_tuple in device_flow_table[direction]:
    #             F = Flow(flow_tuple)
    #             F.set_traffic(list(device_flow_table[direction][flow_tuple]))
    #             self.flows.append(F.key)
    #             flow_table[F.key] = F
    #             F.set_edge_struct()
    #     return flow_table


   

