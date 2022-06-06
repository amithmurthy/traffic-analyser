"""Unpickles persist data and serves user requests from front end """
from email import utils
from msilib.schema import Error
import sys
from flask import request
from utils import unpickle_obj
import json

def _retrieve_data():
    return unpickle_obj("network2.pickle")


def node_endpoint(request_node):
    network_inst = _retrieve_data()
    # if network_inst._is_node(request_node):
        # if node is present 
    
    


if __name__ == "__main__":
    request = dict(json.loads(sys.argv[1]))
    func_dispatcher = {'node': node_endpoint}
    func = next(iter(request))
    func_dispatcher[func](request[func])

