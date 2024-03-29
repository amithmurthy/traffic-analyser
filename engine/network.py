import networkx as nx
from flow import Flow
from node import Node

class Network:
    def __init__(self, network_trace_file):
        self.GraphNetwork = nx.MultiDiGraph() # composite of the nx.Graph() class to access graph network properties 
        self.network_trace_file = network_trace_file
        self.flow_table = {}  # Flow.id aka Flow 5-tuple: Flow() object  
        self.mac_to_ip = {}
        self.first_pkt_datetime = None
        self.nodes = {} # {mac_addr: Node() object, mac_addr: Node() object ....}


    def flow_and_node_factory(self, flow_tuple, pkt_struct):
        """Creational factory method to either create Node and Flow objects and correctly sort their structure - or store pkt_struct"""
        flow_obj = None
        if flow_tuple in self.flow_table:
            flow_obj = self.flow_table[flow_tuple]
        else:
            self.flow_table[flow_tuple] = Flow(flow_tuple)
            flow_obj = self.flow_table[flow_tuple]
            # Append flow obj reference to source and destination nodes
            self._append_flow_to_nodes(src_mac=pkt_struct['eth_src'],dst_mac=pkt_struct['eth_dst'], flow_obj=flow_obj)
        # Append pkt to flow object list
        flow_obj.set_traffic(pkt_struct)
        
    def map_node_ip(self, pkt_struct):
        """ Stores a nodes ip address to create a mac to ip map"""
        def _check_node_ip_map(node, ip_addr):
            node.check_ip_addr(ip_addr)
        
        _check_node_ip_map(self.get_node(pkt_struct['eth_src']), pkt_struct['ip_src'])
        _check_node_ip_map(self.get_node(pkt_struct['eth_dst']), pkt_struct['ip_dst'])
    
    def print_flows(self):
        print(self.flow_table)    
    
    def _append_flow_to_nodes(self, src_mac, dst_mac, flow_obj):
        """Configures the relationship between Node and Flow objects"""
        src_node = self.get_node(src_mac)
        dst_node = self.get_node(dst_mac)
        flow_obj.src_node = src_node
        flow_obj.dst_node = dst_node
        src_node.set_output_flow(flow_obj)
        dst_node.set_input_flow(flow_obj)


    def get_nodes(self):
        return self.nodes

    def set_node_traffic(self, mac_addr, pkt):
        node_obj = self.get_node(mac_addr)
        node_obj.set_traffic(pkt)
    
    def set_first_pkt_datetime(self, first_pkt_datetime):
        self.first_pkt_datetime = first_pkt_datetime
    
    def get_first_pkt_datetime(self):
        return self.first_pkt_datetime

    def get_node(self, mac_addr):
        """Checks if node is in dict: if in it returns else instantiates a new Node object and returns a reference to that. This is strictly to use while parsing pcap file"""
        if mac_addr in self.nodes:
            return self.nodes[mac_addr]
        else:
            self.nodes[mac_addr] = Node(mac_addr)
            self.GraphNetwork.add_node(self.nodes[mac_addr])
            return self.nodes[mac_addr]

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
            self.GraphNetwork.add_node(node_obj)
   

    def _is_node(self, node_key):
        for n in self.GraphNetwork.nodes:
            if n.mac_addr == node_key:
                return n
        return None

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
        for node in self.GraphNetwork.nodes:
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
                    # self.GraphNetwork.add_edge(edge_struct[0], edge_struct[1], attr=edge_struct[2])
                    edge_list.append((edge_struct[0], edge_struct[1], edge_struct[2]['weight']))
        print("FINISHED")
        self.GraphNetwork.add_weighted_edges_from(edge_list)

 
    def _set_node_directional_data(self):
        
        for flow in self.flow_table.values():
            #src is oplink, dst is downlink
            flow.src_node.uplink_total += flow.size
            flow.dst_node.downlink_total += flow.size
        
        


    # def visualise_network_graph(self):
    #     # Need to create a layout when doing
    #     # separate calls to draw nodes and edges
    #     pos = nx.spring_layout(self.GraphNetwork)
    #     edge_list = list(self.GraphNetwork.edges())
    #     nx.draw_networkx_nodes(self.GraphNetwork, pos, cmap=plt.get_cmap('jet'), node_size=500)
    #     nx.draw_networkx_edges(self.GraphNetwork, pos, edgelist=edge_list, edge_color='r', arrows=True)
    #     plt.show()

