from copy import deepcopy
import hashlib


class Flow:
    """this is an edge to a Node object. A Flow belongs to 2 Nodes"""

    def __init__(self, flow_tuple):
        self.tuple = flow_tuple  # Serves as an identifier
        self.traffic = []  # holds all the pkt_structs in the flow
        self.size = 0
        self.duration = 0
        self.src_node = None
        self.dst_node = None

    def set_traffic(self, pkt):
        self.traffic.append(pkt)
        self.size += pkt['payload_size']
        self.duration = pkt['relative_timestamp'] - self.traffic[0]['relative_timestamp']

    def get_tuple(self):
        if self.tuple is not None:
            return self.tuple
        else:
            raise Exception("Flow id not set for instantiated object")

    def get_key(self):
        tuple = str(self.tuple)
        hash_key = hashlib.md5(tuple.encode('utf-8')).hexdigest()
        return hash_key

    # def _set_flow_direction_at_nodes(self):
    #     """As a flow can belong to 2 nodes, this function returns the direction of
    #     the flow by the node calling this function"""
    #     self.direction_at_nodes[self.src_node] = 'output'
    #     self.direction_at_nodes[self.dst_node] = 'input'

    def _get_edge_data(self):
        try:
            assert self.metadata is not None
        except AssertionError as e:
            # if metadata called without it being set -> set metadata
            self._compute_metadata()
        self.edge_data['weight'] = self._get_avg_pkt_size()
        self.edge_data['key'] = self.key

    def set_edge_struct(self):
        self._compute_metadata()
        self._get_edge_data()
        self.edge_struct = (self.tuple[0], self.tuple[1], self.edge_data)

    def get_edge_struct(self):
        try:
            assert self.edge_struct is not None
        except AssertionError as e:
            self.set_edge_struct()
            print("edge struct not set..being set now")
            # raise Exception("Edge struct not computed. Set method called and edge_struct initiated")
        return self.edge_struct

    def _compute_metadata(self):
        """High order method"""
        attributes = ['total_bytes', 'total_pkts', 'duration', 'direction', 'protocol']
        self.metadata = {attr: None for attr in attributes}
        self._get_total_attributes()

    def _get_total_attributes(self):
        self.metadata['total_bytes'] = 0
        self.metadata['total_pkts'] = len(self.traffic)
        self.metadata['duration'] = self.traffic[-1]['relative_timestamp'] - self.traffic[0]['relative_timestamp']
        for pkt in self.traffic:
            if pkt['protocol'] == "TCP":
                payload = pkt['tcp_data']['payload_len']
            elif pkt['protocol'] == "UDP":
                payload = pkt['udp_data']['payload_len']
            elif pkt['protocol'] == "ICMP":
                payload = pkt['icmp_data']['payload_len']
            else:
                try:
                    payload = pkt['payload_len']
                except KeyError:
                    print(pkt['protocol'])
            self.metadata['total_bytes'] += payload

    def _get_avg_pkt_size(self):
        avg_pkt_size = self.metadata['total_bytes'] / self.metadata['total_pkts']
        return avg_pkt_size

# self.metadata = None  # {attribute: value}
# self.edge_data = {}
# self.key = self.get_key()
# self.edge_struct = None  # (n1, n2, object=edge_data)
