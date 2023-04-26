"""Fetches persistent data and serves user requests from front end """
import sys
import jsonpickle
from flask import request
from utils import unpickle_obj
import json
from test_parser import pipe_home_page_data


def getNodeView(request_node):
    # print('entered getNodeView function!', request_node)
    network_inst = unpickle_obj("session_storage.pickle")
    # if network_inst._is_node(request_node):
    # if node is present
    node = network_inst.nodes[request_node]
    response_obj = node.get_throughput()
    print(json.dumps(response_obj))


def run_graph_structure_analysis(file_name):
    data_dir = "/Users/amith/Documents/Study/serialised-data/benign" + '/' + file_name
    draw_network_graph(saved_network_path=data_dir)


def draw_network_graph(saved_network_path: str) -> None:
    """
    Draws the graph network to visualise network structure
    """
    # Fetch saved network instance
    network_instance = unpickle_obj(saved_network_path)
    network_instance.visualise_network_graph()
    # network_instance.visualise_network_graph_3d()

def decode_jsonpickle(serialised_data):
    data = jsonpickle.decode(serialised_data['pipe_home_page_data'])
    print(type(serialised_data['pipe_home_page_data']))
    # data = json.loads(serialised_data['pipe_home_page_data'])
    print('decoded data', data)
    return data

if __name__ == "__main__":
    # run_graph_structure_analysis(str(sys.argv[1]))
    # draw_network_graph(str(sys.argv[1]))
    # print('incoming request format',sys.argv[1])
    request = dict(json.loads(sys.argv[1]))
    # request = decode_jsonpickle(sys.argv[1])
    # print('python request decoded',request)
    # f_request = decode_jsonpickle(request)
    func_dispatcher = {'getNodeView': getNodeView, 'draw_network_graph': draw_network_graph, 'pipe_home_page_data': pipe_home_page_data}
    # # Finds func requested
    func = next(iter(request))
    # network_instance = decode_jsonpickle(request[func])
    # # Dispatches to func with required argument
    func_dispatcher[func](request[func])
