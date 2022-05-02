import networkx as nx
# import matplotlib.pyplot as plt
from node import Node

class Network:
    """Class handles graph based feature analysis and derives from networkx Graph class behaviors/property (i.e., composite of the nx.Graph() class)"""
    def __init__(self, network_trace_file):
        self.network_graph = nx.MultiDiGraph()
        self.network_trace_file = network_trace_file
        self.flow_table = {}  # Flow.id: Flow.traffic reference store for all transport layer traffic 
        self.mac_to_ip = {}

    def set_ip_to_mac_map(self):
        for node in self.Network.nodes:
            for ip in node.ip_addrs:
                self.ip_to_mac_map[ip] = node.mac_addr


    def set_network_trace_obj(self, network_trace_obj):
        self.network_trace_obj = network_trace_obj

    def reset_network_trace_obj(self):
        self.network_trace_obj = None

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


    def _load_node_traffic(self, node, database_pointer):
        file_filter = '_' + self.network_trace_obj.file_name[:-5]
        loaded_device_obj = node.load_device_traffic(file_filter, database_pointer)

        return loaded_device_obj

    def _set_flow_table(self, database_pointer):
        node_count = 0
        for node in self.Network.nodes:
            node_count += 1
            if node_count < len(self.Network.nodes):
                device_obj = self._load_node_traffic(node, database_pointer)
                if node.is_active:

                    self.flow_table.update(node.get_flows(device_obj.flows))

    def _is_internet_node_in_graph(self):
        """ Iterate through GraphNetwork nodes to check its state"""
        _is_internet = False
        for node in self.Network.nodes:
            if node.mac_addr == 'internet':
                _is_internet = True
        return _is_internet

    def _add_internet_node(self):
        internet_node = Node(mac_addr='internet')
        self.Network.add_node(internet_node)

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
