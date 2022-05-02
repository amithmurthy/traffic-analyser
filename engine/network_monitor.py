from tools import unpickle_network_trace_and_device_obj, unpickle_network_graph
import klepto as kl
from packet_parser_control import Path
from network import Network

class NetworkMonitor:
    def __init__(self, database_pointer):
        # Load a list of network_objs
        self.network_trace_instances = unpickle_network_trace_and_device_obj(database_pointer) # this is the number of pcap files in the database
        self.networks = []  # List of NetworkGraph objects
        self.database = database_pointer
        # self.create_networks()

    def create_networks(self, network_trace_limit=1):
        pcap_count = 0
        for network_trace_obj in self.network_trace_instances:
            pcap_count += 1
            if pcap_count > network_trace_limit:
                break
            else:
                network_graph = NetworkGraph()
                network_graph.set_network_trace_obj(network_trace_obj)
                network_graph.add_nodes_and_edges(self.database)
                network_graph.reset_network_trace_obj()
                # self.serialise_pcap_network(input_object=network_graph, name=network_trace_obj.file_name)
                self.networks.append(network_graph)

    @staticmethod
    def serialise_pcap_network(input_object, name):
        file_name = name[:-5]
        save_path = Path(r"C:\Users\amith\Documents\Uni\Masters\app\data") / file_name
        ar = kl.archives.dir_archive(name=str(save_path), serialized=True, cached=True, protocol=4)
        ar['network_graph'] = input_object
        ar.dump()
        ar.clear()

    def run_validation_unit_test(self):
        network_graph = unpickle_network_graph("18-06-10")
