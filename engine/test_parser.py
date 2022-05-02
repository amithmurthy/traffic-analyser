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
# from network import Network


def run_dpkt(file_path):
    read_pkts = 0
    limit = 100
    count = 0
    network = Network(file_path)
    first_pkt_datetime = None
    with open(file_path, 'rb') as f:
        if '.pcapng' in file_path:
            reader = pcapng.Reader(f)
        else:
            reader = pcap.Reader(f)
        pkts = reader.readpkts()
        pkt_volume = len(pkts)
        for t, pkt in pkts:
            count += 1
            if count < limit:
                ether_pkt = Ethernet(pkt)
                pkt_struct = {}
                read_pkts += 1
                print("%.2f" % (count / pkt_volume * 100))
                sys.stdout.flush()
                if count == 1:
                    first_pkt_datetime = datetime.datetime.fromtimestamp(t)
                relative_timestamp = get_relative_timestamp(first_pkt_datetime, datetime.datetime.fromtimestamp(t))
                pkt_struct['relative_timestamp'] = relative_timestamp
                pkt_struct['ether_pkt'] = ether_pkt
                if not isinstance(ether_pkt.data, IP) and not isinstance(ether_pkt.data, IP6):
                    continue
                pkt_struct['ip_pkt'] = ether_pkt.data


                
    sys.stdout.flush()
    # print(rel_ts)

def get_relative_timestamp(first_pkt_timestamp, curr_pkt_timestamp):
    return (curr_pkt_timestamp - first_pkt_timestamp).total_seconds()
 

if __name__ == "__main__":
    file_path = sys.argv[1]
    sys.stdout.flush()
    run_dpkt(file_path)
