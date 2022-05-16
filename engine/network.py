import networkx as nx
from soupsieve import select
# import matplotlib.pyplot as plt
from node import Node


class Network:
    """Class handles graph based feature analysis and derives from networkx Graph class behaviors/property (i.e., composite of the nx.Graph() class)"""
    def __init__(self, network_trace_file):
        self.Network = nx.MultiDiGraph()
        self.network_trace_file = network_trace_file
        self.flow_table = {}  # Flow.id aka Flow 5-tuple: Flow() object  
        self.mac_to_ip = {}
        self.first_pkt_datetime = None
        self.read_pkts = 0
        self.nodes = {} # {mac_addr: Node() object, mac_addr: Node() object ....}
        self.network_traffic = {}

    def get_nodes(self):
        return self.nodes

    def set_node_traffic(self, mac_addr, pkt):
        node_obj = self.get_node(mac_addr)
        node_obj.set_traffic(pkt)
    
    def set_first_pkt_datetime(self, first_pkt_datetime):
        self.first_pkt_datetime = first_pkt_datetime
    
    def get_first_pkt_datetime(self):
        return self.first_pkt_datetime

    def increment_read_pkts(self):
        self.read_pkts += 1
        
    def print_read_pkts(self):
        print(self.read_pkts)
    
    def reset_network_trace_obj(self):
        self.network_trace_obj = None

    def get_node(self, mac_addr):
        """Checks if node is in dict: if in it returns else instantiates a new Node object and returns a reference to that"""
        if mac_addr in self.nodes:
            return self.nodes[mac_addr]
        else:
            self.nodes[mac_addr] = Node(mac_addr)
            return self.nodes[mac_addr]
        
    def initiate_node_key(self, mac_addr):
        self.network_traffic[mac_addr] = []
    
    def append_node_traffic(self, mac_addr, pkt):
        self.network_traffic[mac_addr].append(pkt)

    def add_nodes_and_edges(self, database_pointer):
        self.add_nodes()
        self._set_flow_table(database_pointer)
        self._add_edges()
        self.visualise_network_graph()

    def add_nodes(self, *node_list):
        # get nodes from network_trace_obj
        try:
            assert self.network_trace_obj is not None
        except AssertionError:
            raise Exception("No network_trace_object in object. Either set network_trace_obj or feed in custom node list through optional argument")

        def get_node_addrs():
            if node_list:
                node_addrs = node_list[0]
            else:
                node_addrs = self.network_trace_obj.iot_mac_addr
            return node_addrs

        node_mac_addresses = get_node_addrs()
        for node_mac_addr in node_mac_addresses:
            node_obj = Node(node_mac_addr)
            self.Network.add_node(node_obj)
   

    def _set_flow_table(self, database_pointer):
        node_count = 0
        for node in self.Network.nodes:
            node_count += 1
            if node_count < len(self.Network.nodes):
                device_obj = self._load_node_traffic(node, database_pointer)
                if node.is_active:

                    self.flow_table.update(node.get_flows(device_obj.flows))



   

    def _get_node(self, node_key):
        for n in self.Network.nodes:
            if n.mac_addr == node_key:
                return n

    def convert_ip_edge_to_node_objects(self, ip_edge_struct):
        src_ip = ip_edge_struct[0]
        dst_ip = ip_edge_struct[1]

        def __append_to_map_structures():
            InternetNode = self._get_node("internet")
            if src_ip not in self.ip_to_mac_map:
                InternetNode.ip_addrs.append(src_ip)
                self.ip_to_mac_map[src_ip] = "internet"
            if dst_ip not in self.ip_to_mac_map:
                InternetNode.ip_addrs.append(dst_ip)
                self.ip_to_mac_map[dst_ip] = "internet"


        __append_to_map_structures()

        src_node = self._get_node(self.ip_to_mac_map[src_ip])
        dst_node = self._get_node(self.ip_to_mac_map[dst_ip])
        mac_edge_struct = (src_node, dst_node, ip_edge_struct[2])
        return mac_edge_struct

    def _add_edges(self):
        self.set_ip_to_mac_map()
        if not self._is_internet_node_in_graph():
            self._add_internet_node()
        edge_list = []
        for node in self.Network.nodes:
            for flow_key in node.flows:
                FlowObject = self.flow_table[flow_key]
                # set edge struct
                FlowObject.set_edge_struct()
                ip_edge_struct = FlowObject.get_edge_struct()
                edge_struct = self.convert_ip_edge_to_node_objects(ip_edge_struct)
                # print(edge_struct)
                if edge_struct[0] == edge_struct[1]:
                    continue
                else:
                    # self.Network.add_edge(edge_struct[0], edge_struct[1], attr=edge_struct[2])
                    edge_list.append((edge_struct[0], edge_struct[1], edge_struct[2]['weight']))
        print("FINISHED")
        self.Network.add_weighted_edges_from(edge_list)

    # def visualise_network_graph(self):
    #     # Need to create a layout when doing
    #     # separate calls to draw nodes and edges
    #     pos = nx.spring_layout(self.Network)
    #     edge_list = list(self.Network.edges())
    #     nx.draw_networkx_nodes(self.Network, pos, cmap=plt.get_cmap('jet'), node_size=500)
    #     nx.draw_networkx_edges(self.Network, pos, edgelist=edge_list, edge_color='r', arrows=True)
    #     plt.show()
