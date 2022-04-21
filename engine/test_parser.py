import sys
import datetime
from dpkt import pcap, pcapng
from dpkt.ethernet import *
import os
import math



def run_dpkt(file):
    read_pkts = 0
    limit = 10
    count = 0
    epochs = []
    date_time = []
    print('parsing function hit')
    sys.stdout.flush()
    first_pkt_datetime = None
    rel_ts = []
    with open(file, 'rb') as f:
        if '.pcapng' in file:
            reader = pcapng.Reader(f)
        else:
            reader = pcap.Reader(f)
        pkts = reader.readpkts()
        # pkt_volume = len(pkts)
        # print(pkt_volume)
        # pkt_volume = 567650
        print("size of pkts", sys.getsizeof(reader))
        for t, pkt in pkts:
            count += 1
            if count < limit:
                ether_pkt = Ethernet(pkt)
                pkt_struct = {}
                read_pkts += 1
                # print("%.2f" % (float(read_pkts) / pkt_volume * 100))
                sys.stdout.flush()
                print(t)
                # if count == 1:
                #     first_pkt_datetime = datetime.datetime.fromtimestamp(t)
                # relative_timestamp = get_relative_timestamp(first_pkt_datetime, datetime.datetime.fromtimestamp(t))
                # rel_ts.append(relative_timestamp)
                # pkt_struct['relative_timestamp'] = relative_timestamp
                # pkt_struct['ether_pkt'] = ether_pkt
                

    # print(rel_ts)    


def get_relative_timestamp(first_pkt_timestamp, curr_pkt_timestamp):
    return (curr_pkt_timestamp - first_pkt_timestamp).total_seconds()


if __name__ == "__main__":
    file_path = sys.argv[1]
    print('PYTHON EXECUTING')
    sys.stdout.flush()
    run_dpkt(file=file_path)

