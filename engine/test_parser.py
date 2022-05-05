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
import os
import math
from network import Network
from multiprocessing import Pool, Value, Array
from ctypes import c_wchar, c_wchar_p
import pickle
import tqdm

read_pkts = Value('i', 0)
# first_pkt_datetime = Array(c_wchar, '')
# first_pkt_datetime = Value(c_wchar_p, 'start')


def read_pkt_hdrs(pkts):
    global read_pkts

    first_pkt_datetime = _get_first_pkt_datetime()
    
    for t, pkt in pkts:
        ether_pkt = Ethernet(pkt)
        pkt_struct = {}
        relative_timestamp = get_relative_timestamp(first_pkt_datetime, datetime.datetime.fromtimestamp(t))
        pkt_struct['relative_timestamp'] = relative_timestamp
        pkt_struct['ether_pkt'] = ether_pkt
        if not isinstance(ether_pkt.data, IP) and not isinstance(ether_pkt.data, IP6):
            continue
        pkt_struct['ip_pkt'] = ether_pkt.data
        

def get_chunks(pkts, pkt_volume, n):
    return [pkts[i:i+n] for i in range(0, pkt_volume, n)]


def _pickle_first_pkt_datetime(first_pkt_datetime):
    with open('first_pkt_datetime.pickle', 'wb') as f:
        pickle.dump(first_pkt_datetime,f)
    
def _get_first_pkt_datetime():
    with open('first_pkt_datetime.pickle', 'rb') as f:
        first_pkt_datetime = pickle.load(f)
    return first_pkt_datetime

def run_dpkt(file_path):
    # limit = 5
    # count = 0
    # network = Network(file_path)
    
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
        pool = Pool(4)
        # pool.map(read_pkt_hdrs, split_pkt_list) 
        for _ in tqdm.tqdm(pool.imap_unordered(read_pkt_hdrs, split_pkt_list), total=len(split_pkt_list)):
            pass


    sys.stdout.flush()
    # print(rel_ts)

def get_relative_timestamp(first_pkt_timestamp, curr_pkt_timestamp):
    return (curr_pkt_timestamp - first_pkt_timestamp).total_seconds()

if __name__ == "__main__":
    file_path = sys.argv[1]
    run_dpkt(file_path)
    

