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
        pkt_struct['ether_src'] = mac_addr(ether_pkt.src)
        pkt_struct['ether_dst'] = mac_addr(ether_pkt.dst)
        if not isinstance(ether_pkt.data, IP) and not isinstance(ether_pkt.data, IP6):
            continue
        pkt_struct['ip_pkt'] = ether_pkt.data
        ip_pkt = ether_pkt.data
        pkt_struct['ip_src'] = inet_to_str(ip_pkt.src)
        pkt_struct['ip_dst'] = inet_to_str(ip_pkt.dst)

        if isinstance(ip_pkt.data, TCP) or isinstance(ip_pkt.data, UDP):
            transport_pkt = None
            protocol = None
            if isinstance(ip_pkt, TCP):
                transport_pkt = ip_pkt.data
                protocol = 'TCP'
            else:
                transport_pkt = ip_pkt.data
                protocol = 'UDP'
            set_ports(pkt_struct, transport_pkt)
            pkt_struct['transport_protocol'] = protocol
            flow_tuple = (pkt_struct['ip_src'], pkt_struct['ip_dst'], pkt_struct['sport'], pkt_struct['dport'], protocol)
            # Append to flow traffic
            # TODO: Only Flow objects should store the traffic data, Node and Network objects only store references to the flow objects -> this enables more flow-level commputations to be abstracted and handled by the flow object
        else:
            # support only tcp and udp for mvp -> so save ip traffic 
            pkt_struct['ip_len'] = ip_pkt.len if isinstance(ip_pkt, IP) else ip_pkt.plen
            network_inst.set_node_traffic(pkt_struct['ether_src'], pkt_struct)
            network_inst.set_node_traffic(pkt_struct['ether_dst'], pkt_struct)  
    
def get_chunks(pkts, pkt_volume, n):
    return [pkts[i:i+n] for i in range(0, pkt_volume, n)]

def run_parsing(file_path, network_inst):
    
    with open(file_path, 'rb') as f:
        if '.pcapng' in file_path:
            reader = pcapng.Reader(f)
        else:
            reader = pcap.Reader(f)
        pkts = reader.readpkts() # Loads list of tuples (pkt info) into memory
        pkts = pkts[:10]
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

def validate_multiprocess_output(file_path):
    network = Network(file_path)
    
    with open(file_path, 'rb') as f:
        if '.pcapng' in file_path:
            reader = pcapng.Reader(f)
        else:
            reader = pcap.Reader(f)
        pkts = reader.readpkts() # Loads list of tuples (pkt info) into memory
        # pkts = pkts[:100000]
        # print('pkts len',len(pkts))
        first_pkt_datetime = datetime.datetime.fromtimestamp(pkts[0][0])
        start = time.time()
        for t, pkt in pkts:
            ether_pkt = Ethernet(pkt)
            pkt_struct = {}
            relative_timestamp = get_relative_timestamp(first_pkt_datetime, datetime.datetime.fromtimestamp(t))
            pkt_struct['relative_timestamp'] = relative_timestamp
            pkt_struct['ether_src'] = mac_addr(ether_pkt.src)
            pkt_struct['ether_dst'] = mac_addr(ether_pkt.dst)
            
            if not isinstance(ether_pkt.data, IP) and not isinstance(ether_pkt.data, IP6):
                continue
            ip_pkt = ether_pkt.data
            pkt_struct['ip_src'] = inet_to_str(ip_pkt.src)
            pkt_struct['ip_dst'] = inet_to_str(ip_pkt.dst)

            if isinstance(ip_pkt.data, TCP):
                tcp_pkt = ip_pkt.data
                set_ports(pkt_struct, tcp_pkt)
            elif isinstance(ip_pkt.data, UDP):
                udp_pkt = ip_pkt.data
                set_ports(pkt_struct, udp_pkt) 
            else:
                # support only tcp and udp for mvp -> so save ip traffic 
                pkt_struct['ip_len'] = ip_pkt.len if isinstance(ip_pkt, IP) else ip_pkt.plen
                network.set_node_traffic(pkt_struct['ether_src'], pkt_struct)
                network.set_node_traffic(pkt_struct['ether_dst'], pkt_struct)
                continue
        end = time.time()
        print('time', end - start)            
    # pickle_obj(name='sequetial_nodes', obj=network.get_nodes())
    # multiprocessed_nodes = unpickle_obj('nodes.pickle')
    # sequential_nodes = network.get_nodes()

    # # print(multiprocessed_nodes)
    # # print(sequential_nodes)

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



def get_relative_timestamp(first_pkt_timestamp, curr_pkt_timestamp):
    return (curr_pkt_timestamp - first_pkt_timestamp).total_seconds()


if __name__ == "__main__":
    file_path = sys.argv[1]
    
    # NetworkProxy = Proxy(Network)
    BaseManager.register('Network', Network) # if want to share class attributes:  BaseManager.register('Network', Network, NetworkProxy) 
    manager = BaseManager()
    manager.start()
    network_inst = manager.Network(file_path)
    run_parsing(file_path, network_inst)
    # pickle_obj(name='nodes',obj=network_inst.get_nodes())
    # validate_multiprocess_output(file_path)
