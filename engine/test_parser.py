from multiprocessing.managers import BaseManager
import sys
import datetime
from dpkt import pcap, pcapng
from dpkt.ethernet import *
from dpkt.ip import IP
from dpkt.ip6 import IP6
from dpkt.tcp import TCP
from dpkt.udp import UDP
from utils import mac_addr, inet_to_str
import utils
import itertools
import math
from network import Network
from multiprocessing import Pool, Value
from multiprocessing.managers import BaseManager
from ctypes import c_wchar, c_wchar_p
import pickle
import tqdm

read_pkts = Value('i', 0)
# first_pkt_datetime = Array(c_wchar, '')
# first_pkt_datetime = Value(c_wchar_p, 'start')

def read_pkt_hdrs(network_inst, pkts):
    first_pkt_datetime = _get_first_pkt_datetime()
    # network_inst = input[0]
    # pkts = input[1]
    for t, pkt in pkts:
        ether_pkt = Ethernet(pkt)
        pkt_struct = {}
        relative_timestamp = get_relative_timestamp(first_pkt_datetime, datetime.datetime.fromtimestamp(t))
        pkt_struct['relative_timestamp'] = relative_timestamp
        pkt_struct['ether_src'] = mac_addr(ether_pkt.src)
        pkt_struct['ether_dst'] = mac_addr(ether_pkt.dst)
        
        # if not isinstance(ether_pkt.data, IP) and not isinstance(ether_pkt.data, IP6):
        #     continue
        # pkt_struct['ip_pkt'] = ether_pkt.data
        if network_inst.is_node_present(pkt_struct['ether_src']):
            network_inst.append_node_traffic(pkt_struct['ether_src'],pkt_struct)
        else:
            network_inst.initiate_node_key(pkt_struct['ether_src'])
            network_inst.append_node_traffic(pkt_struct['ether_src'], pkt_struct)


def get_chunks(pkts, pkt_volume, n):
    return [pkts[i:i+n] for i in range(0, pkt_volume, n)]


def _pickle_first_pkt_datetime(first_pkt_datetime):
    with open('first_pkt_datetime.pickle', 'wb') as f:
        pickle.dump(first_pkt_datetime,f)
    
def _get_first_pkt_datetime():
    with open('first_pkt_datetime.pickle', 'rb') as f:
        first_pkt_datetime = pickle.load(f)
    return first_pkt_datetime

def run_dpkt(file_path, network_inst):
    # limit = 5
    # count = 0
    print('test print:', network_inst.file_path)
    
    with open(file_path, 'rb') as f:
        if '.pcapng' in file_path:
            reader = pcapng.Reader(f)
        else:
            reader = pcap.Reader(f)
        pkts = reader.readpkts() # Loads list of tuples (pkt info) into memory
        pkts = pkts[:150]
        pkt_volume = len(pkts)
        n = math.floor(pkt_volume / 4)
        first_pkt_datetime = datetime.datetime.fromtimestamp(pkts[0][0])
        _pickle_first_pkt_datetime(first_pkt_datetime)
        split_pkt_list = get_chunks(pkts, pkt_volume, n)
        input = zip(itertools.repeat(network_inst), split_pkt_list)
        print(input)
        pool = Pool(4)
        pool.starmap(read_pkt_hdrs, input) 
        
        # for _ in tqdm.tqdm(pool.imap_unordered(read_pkt_hdrs, split_pkt_list), total=len(split_pkt_list)):
        #     pass

    print('process finished')
    # print(network_inst.print_network_traffic())
    print(network_inst.file_path)
    sys.stdout.flush()
    # print(rel_ts)

def get_relative_timestamp(first_pkt_timestamp, curr_pkt_timestamp):
    return (curr_pkt_timestamp - first_pkt_timestamp).total_seconds()

if __name__ == "__main__":
    file_path = sys.argv[1]
    BaseManager.register('Network', Network)
    manager = BaseManager()
    manager.start()
    network_inst = manager.Network(file_path)
    run_dpkt(file_path, network_inst)
