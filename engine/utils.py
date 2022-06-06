"""
Use DPKT to read in a pcap file and print out the contents of the packets
This example is focused on the fields in the Ethernet Frame and IP packet
"""
import time
import dpkt
import datetime
import socket
from dpkt.compat import compat_ord
import pickle
from copy import deepcopy

def mac_addr(address):
    """Convert a MAC address to a readable/printable string

       Args:
           address (str): a MAC address in hex form (e.g. '\x01\x02\x03\x04\x05\x06')
       Returns:
           str: Printable/readable MAC address
    """
    return ':'.join('%02x' % compat_ord(b) for b in address)



def inet_to_str(inet):
    """Convert inet object to a string

        Args:
            inet (inet struct): inet network address
        Returns:
            str: Printable/readable IP address
    """
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

def pickle_obj(name, obj, isNetworkProxy):
    if isNetworkProxy:
        n = deepcopy(obj)
        print('object type',type(n))
        with open(name + '.pickle', 'wb') as f:
            pickle.dump(n,f)
    else:
        with open(name + '.pickle', 'wb') as f:
            pickle.dump(obj,f)
    
def unpickle_obj(input_pickle):
    print('unpickling')
    with open(input_pickle, 'rb') as f:
        return pickle.load(f)

# def timeit(f):
    
#     def timed(*args, **kw):

#         ts = time.time()
#         result = f(*args, **kw)
#         te = time.time()

#         print('func:%r args:[%r, %r] took: %2.4f sec' % \
#           (f.__name__, args, kw, te-ts))
#         return result

#     return timed