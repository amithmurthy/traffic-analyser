from multiprocessing.managers import BaseManager
import sys
import datetime
from time import time
from dpkt import pcap, pcapng
from dpkt.ethernet import *
from dpkt.ip import IP
from dpkt.ip6 import IP6
from dpkt.tcp import TCP
from dpkt.udp import UDP
from utils import mac_addr, inet_to_str, pickle_obj, unpickle_obj
import itertools
import math
from network import Network
from multiprocessing import Pool, Value
from multiprocessing.managers import BaseManager, NamespaceProxy
import time
import types
import json

read_pkts = Value('i', 0)
# first_pkt_datetime = Array(c_wchar, '')
# first_pkt_datetime = Value(c_wchar_p, 'start')

# class NetworkProxy(NamespaceProxy):
#     _exposed = tuple(dir(Network))

#     def __getattr__(self, name):
#         result = super().__getattr__(name)
#         if isinstance(result, types.MethodType):
#             def wrapper(*args, **kwargs):
#                 self._callmethod(name, args, kwargs)
#             return wrapper
#         return result


# def Proxy(target):
#     """AutoProxy function that exposes a custom Proxy class """

#     dic = {'types': types}
#     exec('''def __getattr__(self, key):
#         result = self._callmethod('__getattribute__', (key,))
#         if isinstance(result, types.MethodType):
#             def wrapper(*args, **kwargs):
#                 self._callmethod(key, args, kwargs)
#             return wrapper
#         return result''', dic)
#     proxyName = target.__name__ + "Proxy"
#     ProxyType = type(proxyName, (NamespaceProxy,), dic)
#     ProxyType._exposed_ = tuple(dir(target))
#     return ProxyType


def read_pkt_hdrs(network_inst, pkts):
    
    first_pkt_datetime = network_inst.get_first_pkt_datetime()
    for t, pkt in pkts:
        ether_pkt = Ethernet(pkt)
        pkt_struct = {}
        relative_timestamp = get_relative_timestamp(first_pkt_datetime, datetime.datetime.fromtimestamp(t))
        pkt_struct['relative_timestamp'] = relative_timestamp
        pkt_struct['eth_src'] = mac_addr(ether_pkt.src)
        pkt_struct['eth_dst'] = mac_addr(ether_pkt.dst)
        if not isinstance(ether_pkt.data, IP) and not isinstance(ether_pkt.data, IP6):
            continue
        pkt_struct['ip_pkt'] = ether_pkt.data
        ip_pkt = ether_pkt.data
        pkt_struct['ip_src'] = inet_to_str(ip_pkt.src)
        pkt_struct['ip_dst'] = inet_to_str(ip_pkt.dst)
        network_inst.map_node_ip(pkt_struct)
        protocol = None
        if isinstance(ip_pkt.data, TCP) or isinstance(ip_pkt.data, UDP):
            transport_pkt = None
            if isinstance(ip_pkt, TCP):
                transport_pkt = ip_pkt.data
                protocol = 'TCP'
                pkt_struct['flags'] = transport_pkt.flags
                pkt_struct['win_size'] = transport_pkt.win
                pkt_struct['ack'] = transport_pkt.ack
                pkt_struct['payload_size'] = len(transport_pkt) 
            else:
                transport_pkt = ip_pkt.data
                protocol = 'UDP'
                pkt_struct['payload_size'] = len(transport_pkt)
            set_ports(pkt_struct, transport_pkt)
            pkt_struct['transport_protocol'] = protocol
            flow_tuple = (pkt_struct['ip_src'], pkt_struct['ip_dst'], pkt_struct['sport'], pkt_struct['dport'], protocol)
        else:
            # support only tcp and udp for mvp -> so save ip traffic 
            protocol = 'IP'
            pkt_struct['ip_len'] = ip_pkt.len if isinstance(ip_pkt, IP) else ip_pkt.plen
            flow_tuple = (pkt_struct['ip_src'], pkt_struct['ip_dst'], protocol) 
        
        # Only Flow objects should store the traffic data, Node and Network objects only store references to the flow objects -> this enables more flow-level commputations to be abstracted and handled by the flow object
        network_inst.sort_flow_traffic(flow_tuple, pkt_struct)
    
def get_chunks(pkts, pkt_volume, n):
    return [pkts[i:i+n] for i in range(0, pkt_volume, n)]

def run_parsing(file_path, network_inst):
    
    with open(file_path, 'rb') as f:
        if '.pcapng' in file_path:
            reader = pcapng.Reader(f)
        else:
            reader = pcap.Reader(f)
        pkts = reader.readpkts() # Loads list of tuples (pkt info) into memory
        # pkts = pkts[:10]
        pkt_volume = len(pkts)
        print(pkt_volume)
        n = math.floor(pkt_volume / 4)
        first_pkt_datetime = datetime.datetime.fromtimestamp(pkts[0][0])
        network_inst.set_first_pkt_datetime(first_pkt_datetime)
        split_pkt_list = get_chunks(pkts, pkt_volume, n)
        input = zip(itertools.repeat(network_inst), split_pkt_list)
        pool = Pool()
        start = time.time()
        pool.starmap(read_pkt_hdrs, input) 
        end = time.time()
        print('time', end - start)
    sys.stdout.flush()


def set_ports(pkt_struct, transport_pkt):
    pkt_struct['sport'] = transport_pkt.sport
    pkt_struct['dport'] = transport_pkt.dport


def validate_network_obj():
    multiprocessed_network_obj = unpickle_obj('network.pickle')
    sequential_network_obj = unpickle_obj('network2.pickle')

    # Validate flows 
    s_flows = list(sequential_network_obj.flow_table.keys())
    m_flows = list(multiprocessed_network_obj.flow_table.keys())


    # for key in multiprocessed_nodes:
    #     m_node = multiprocessed_nodes[key]
    #     s_node = sequential_nodes[key]
    #     if len(m_node.traffic) == len(s_node.traffic):
    #         # If the timestamp of pkt_structs in Node.traffic is different => multiprocessing has been successfully implemented 
    #         m_rel_ts = [pkt['relative_timestamp'] for pkt in m_node.traffic] # work done in parallel (m)
    #         s_rel_ts = [pkt['relative_timestamp'] for pkt in s_node.traffic] # work done sequentially (s)
    #         for i in range(len(m_rel_ts)):
    #             if m_rel_ts[i] != s_rel_ts[i]:
    #                 print('timestamp not equal')
    #     else:
    #         print('NOT EQUAL, FAILED') 
    

def get_graph_data(network):
    graph_data = {
        'nodes': [ {'id': mac_addr, 'label':mac_addr, 'title': mac_addr} for mac_addr in network.nodes],
        'edges':[]
    }
    
    for flow_id in network.flow_table:
        flow = network.flow_table[flow_id]
        edge = {'from':flow.src_node.mac_addr,'to':flow.dst_node.mac_addr} 
        if edge not in graph_data['edges']:
            graph_data['edges'].append(edge)
        else:
            continue
    # std out returns data to PythonShell process in main (main.js Electron) process
    return graph_data
    

def set_networkx_edges(network_inst):
    for flow_id in network_inst.flow_table:
        flow_obj = network_inst.flow_table[flow_id]
        # edge = (flow_obj.src_node, flow_obj.dst_node)
        network_inst.GraphNetwork.add_edge(flow_obj.src_node,flow_obj.dst_node, weight=flow_obj.size)
        print('size',flow_obj.size,'duration', flow_obj.duration,'no. of pkts', len(flow_obj.traffic))

def get_node_table(network):
    node_table = []
    for node in network.GraphNetwork.nodes:
        node_data = {'mac_addr':node.mac_addr, 'uplink_total': node.uplink_total, 'downlink_total':node.downlink_total}
        node_table.append(node_data)
    return node_table

def pipe_home_page_data(network):
    network._set_node_directional_data()
    response_obj = {'network_graph': get_graph_data(network), 'node_table':get_node_table(network)}
    print(json.dumps(response_obj))
    
def parse_sequentially(file_path):
    network = Network(file_path)
    pkts_read = 0
    with open(file_path, 'rb') as f:
        if '.pcapng' in file_path:
            reader = pcapng.Reader(f)
        else:
            reader = pcap.Reader(f)
        pkts = reader.readpkts() # Loads list of tuples (pkt info) into memory
        pkts = pkts[:1000]
        pkt_volume = len(pkts)
        # print('pkts len',len(pkts))
        first_pkt_datetime = datetime.datetime.fromtimestamp(pkts[0][0])
        start = time.time()
        for t, pkt in pkts:
            # print(pkts_read / pkt_volume * 100)
            ether_pkt = Ethernet(pkt)
            pkt_struct = {}
            relative_timestamp = get_relative_timestamp(first_pkt_datetime, datetime.datetime.fromtimestamp(t))
            pkt_struct['relative_timestamp'] = relative_timestamp
            pkt_struct['eth_src'] = mac_addr(ether_pkt.src)
            pkt_struct['eth_dst'] = mac_addr(ether_pkt.dst)
            
            if not isinstance(ether_pkt.data, IP) and not isinstance(ether_pkt.data, IP6):
                continue
            ip_pkt = ether_pkt.data
            pkt_struct['ip_src'] = inet_to_str(ip_pkt.src)
            pkt_struct['ip_dst'] = inet_to_str(ip_pkt.dst)
            protocol = None
            if isinstance(ip_pkt.data, TCP) or isinstance(ip_pkt.data, UDP):
                transport_pkt = None
                if isinstance(ip_pkt, TCP):
                    transport_pkt = ip_pkt.data
                    protocol = 'TCP'
                    pkt_struct['flags'] = transport_pkt.flags
                    pkt_struct['win_size'] = transport_pkt.win
                    pkt_struct['ack'] = transport_pkt.ack
                    pkt_struct['payload_size'] = len(transport_pkt) 
                else:
                    transport_pkt = ip_pkt.data
                    protocol = 'UDP'
                    pkt_struct['payload_size'] = len(transport_pkt)
                set_ports(pkt_struct, transport_pkt)
                pkt_struct['transport_protocol'] = protocol
                flow_tuple = (pkt_struct['ip_src'], pkt_struct['ip_dst'], pkt_struct['sport'], pkt_struct['dport'], protocol)
            else:
                # support only tcp and udp for mvp -> so save ip traffic 
                protocol = 'IP'
                pkt_struct['payload_size'] = ip_pkt.len if isinstance(ip_pkt, IP) else ip_pkt.plen
                flow_tuple = (pkt_struct['ip_src'], pkt_struct['ip_dst'], protocol) 
            # Send flow tuple and pkt struct to flow and node factory to sort the pkt into flow object and Node obj
            network.flow_and_node_factory(flow_tuple, pkt_struct)
            pkts_read += 1 
        end = time.time()
    
    pickle_obj(name='network2', obj=network, isNetworkProxy=False) 
    # print('time', end - start)  
    # set_networkx_edges(network)
    pipe_home_page_data(network)

def get_relative_timestamp(first_pkt_timestamp, curr_pkt_timestamp):
    return (curr_pkt_timestamp - first_pkt_timestamp).total_seconds()

def validate_pickled_obj():
    network_obj = unpickle_obj('network.pickle')
    print(network_obj.flow_table)

    

if __name__ == "__main__":
    file_path = sys.argv[1]
    # validate_pickled_obj()
    # NetworkProxy = Proxy(Network)
    # BaseManager.register('Network', Network) # if want to share class attributes:  BaseManager.register('Network', Network, NetworkProxy) 
    # manager = BaseManager()
    # manager.start()
    # network_inst = manager.Network(file_path)
    # run_parsing(file_path, network_inst)
    # pickle_obj(name='network', obj=network_inst, isNetworkProxy=True)
    parse_sequentially(file_path)
    # validate_network_obj()