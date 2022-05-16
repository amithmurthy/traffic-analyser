from flow import Flow


class Node:
    """Node to a NetworkGraph"""
    def __init__(self, mac_addr):
        self.mac_addr = mac_addr
        self.name = None
        self.ip_addrs = []
        self.traffic = [] # List of pkt_structs (ingress and egress) 
        self.is_active = None
        self.inputs_flows = None
        self.output_flows = None
        self.flows = []
    
    def set_traffic(self, pkt):
        self.traffic.append(pkt)

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


   

