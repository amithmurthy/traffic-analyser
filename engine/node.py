from flow import Flow


class Node:
    """Node to a NetworkGraph"""
    def __init__(self, mac_addr):
        self.mac_addr = mac_addr
        self.name = None
        self.ip_addrs = []
        self.is_active = None
        self.input_flows = []
        self.output_flows = []
        self.all_flows = []
    
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

    # def set_directional_flows(self):


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


   

