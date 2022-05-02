from ast import Raise
from pathlib import Path

from zmq import device
import trace_filtering
import klepto as kl
from device import DeviceProfile
import math
import re
import time
from datetime import datetime
import matplotlib.pyplot as plt
import logging
logging.basicConfig(level=logging.INFO)


def halve_dict(large_dict):
    large_dict = large_dict
    dict1 = dict(list(large_dict.items())[len(large_dict) // 2:])
    dict2 = dict(list(large_dict.items())[:len(large_dict) // 2])
    return dict1, dict2

def save_traffic(NetworkTraffic, file_path,devices):
    path = file_path+str('\_')+NetworkTraffic.file_name
    folder = Path(path)
    if folder.is_dir():
        pass
    else:
        folder.mkdir(parents=True)

    trace_filtering.shelve_network_info(NetworkTraffic, path+'\_network_info')
    for device in devices:
        if "Router" in device.device_name:
            continue
        trace_filtering.shelve_device_traffic(device, path+'\_' +device.device_name + "-db")


def unpickle_device_objects(file_path, device_filter, dataset_type):
    """Loads processed traffic and returns device objects for a specific device, and network object for each tracefile"""

    database = Path(file_path)
    import re
    device_objects = []
    network_objects = []
    count = 0
    limit = 2 #This is for logic testing purposes  math.inf
    files = []
    for network_trace in database.iterdir():
        count += 1
        if count > limit:
            break
        network_trace_file_path = file_path+'\_'+str(network_trace)[-8:]
        for device_folder in network_trace.iterdir():
            # print(device_folder)
            file_name = re.search('_(.+?)-db', device_folder.name)
            if file_name:
                device_name = file_name.group(1)
                if device_name == device_filter:
                    files.append("20" + str(network_trace)[-8:])
                    device_obj = open_device_archive(network_trace_file_path+'\_'+device_name+'-db')
                    device_objects.append(device_obj)
                    network_obj = open_network_archive(network_trace_file_path + "/_network_info", str(network_trace)[-8:] + ".pcap")
                    network_objects.append(network_obj)

    if dataset_type == "benign":
        return device_objects, network_objects
    else:
        return device_objects, network_objects, files



def unpickle_network_trace_and_device_obj(file_path, **kwargs):
    # print("loading files")
    network_trace_devices = {} #{NetworkTrace:[DeviceProfile, DeviceProfile...]}

    database = Path(file_path)
    # Count will limit the number of network_traces unpickled
    count = 0
    file_filter = kwargs['files'] if 'files' in kwargs.keys() else None
    # print("file_filter", file_filter)
    device_filter = kwargs['devices'] if 'devices' in kwargs.keys() else None
    if type(device_filter) is not list:
        device_filter = [device_filter]
    # print("device filter", device_filter)
    limit = kwargs['limit'] if 'limit' in kwargs.keys() else math.inf
    is_device_traffic = kwargs['is_device_traffic'] if 'is_device_traffic' in kwargs.keys() else False
    extract_timestamp_dict = kwargs['extract_timestamp'] if 'extract_timestamp' in kwargs.keys() else False
    for network_trace in database.iterdir():
        count += 1
        if count > limit:
            break
        if file_filter is not None:
            # print(str(network_trace)[-9:])
            if str(network_trace)[-9:] not in file_filter: #or str(network_trace)[-9:] != file_filter:
                continue
        network_trace_file_path = file_path + '\_' + str(network_trace)[-8:]
        print("Unpickling", network_trace)
        network_obj = open_network_archive(network_trace_file_path + "/_network_info",
                                           str(network_trace)[-8:] + ".pcap", extract_timestamp_dict)
        network_trace_devices[network_obj] = []
        for device_folder in network_trace.iterdir():
            file_name = re.search('_(.+?)-db', device_folder.name)
            if file_name:
                device_name = file_name.group(1)
                if "Router" in device_name:
                    continue
                if device_name not in device_filter:
                    continue
                print(device_name)
                device_obj = open_device_archive(network_trace_file_path + '\_' + device_name + '-db')
                network_trace_devices[network_obj].append(device_obj)
    if is_device_traffic and device_filter is not None:
        # only return a list of device_obj instances for a device_filter
        device_traffic_list = list(network_trace_devices.values())
        if type(device_traffic_list[0]) == list:
            flat_traffic_list = []
            for sublist in device_traffic_list:
                for item in sublist:
                    flat_traffic_list.append(item)
            return flat_traffic_list
        else:
            return device_traffic_list
    return network_trace_devices

def open_network_archive(directory, file_name, extract_timestamp_dict):
    d = kl.archives.dir_archive(name=directory, serialized= True)
    d.load('mac_to_ip')
    if extract_timestamp_dict is True:
        d.load('ordinal_timestamp')
    from network import NetworkTrace
    return NetworkTrace(file_name, None,d['mac_to_ip'])

def open_device_archive(directory):
    # print(directory)
    d = kl.archives.dir_archive(name=directory, serialized=True)
    # print(d.archive._keydict())
    d.load('ip_addrs')
    # print(d['ip_addrs'])
    d.load('device_traffic')
    d.load('mac_addr')
    d.load('device_name')
    # try:
    #     print(d['ip_addrs'])
    #     print(d.archive._keydict())
    # except:
    #     print(d.archive._keydict())
    try:
        return DeviceProfile(d['device_name'], d['mac_addr'], d['ip_addrs'], d['device_traffic'])
    except KeyError as e:
        print(d['device_name'])
        raise KeyError('Key error in one of the fields')


def create_device_plots(devices, malicious_pkts, benign_pkts):

    for device in devices:
        device.update_profile(malicious_pkts, benign_pkts)

def unpickle_network_graph(file_name):

    database = Path(r"D:\app\data")

    for pcap_fie_dir in database.iterdir():
        print(pcap_fie_dir.name)
        if pcap_fie_dir.name == file_name:
            d = kl.archives.dir_archive(name=str(database / pcap_fie_dir.name), serialized=True)
            d.load('network_graph')
            return d['network_graph']





def get_malicious_flows(*folder_path):
    folder = Path(folder_path) if folder_path else Path(r"C:\Users\amith\Documents\Uni\Masters\Datasets\UNSW\2018\annotations\annotations")
    malicious_flows = {}

    for file in folder.iterdir():
        if "packet" in file.name:
            device_mac_int = str(file.name)[:12]
            # Need to convert the string so its stored in the right format
            device = ":".join(device_mac_int[i:i + 2] for i in range(0, len(device_mac_int), 2))
            malicious_flows[device] = {}
            with open(file, 'r') as txtfile:
                # mylist = [line.rstrip('\n') for line in txtfile]
                # line = txtfile.readline()
                # print(file.name)
                for line in txtfile:
                    elements = line.split(',')
                    proto = None
                    if elements[6] == '6':
                        proto = "TCP"
                    elif elements[6] == '17':
                        proto = "UDP"
                    date = datetime.utcfromtimestamp(int(elements[0])/1000).strftime('%Y-%m-%d')
                    # date_2 = time.strftime('%Y-%m-%d', time.localtime(int(elements[0])/1000))
                    if date in malicious_flows[device]:
                        malicious_flows[device][date].append((elements[4], elements[5], int(elements[7]), int(elements[8]), proto))
                    else:
                        malicious_flows[device][date] = []
                        malicious_flows[device][date].append((elements[4], elements[5], int(elements[7]), int(elements[8]), proto))

    return malicious_flows

def get_device_cluster(device, location, feature_set, time_window, s_rate):
    device_cluster = {
        'Belkin wemo motion sensor': {'FS2': {'120': {'10': {'internet': 32, 'local': 32, 'all': 156}, '30': {'internet': 32, 'local': 32}, '60':{'internet': 32,'local': 32}},
                                              '240': {'10': {'internet': 32, 'local': 32}, '30': {'internet': 32, 'local': 32}, '60':{'internet': 32,'local': 32}}},
                                      'FS3': {'120': {'10': {'internet': 64, 'local': 64, 'all': 32},'30': {'internet': 32, 'local': 32, 'all': 32}, '60': {'internet': 128, 'local': 128, 'all': 32}},
                                              '240': {'10': {'internet': 32, 'local': 32, 'all': 32},'30': {'internet': 32, 'local': 32, 'all': 32}, '60': {'internet': 32, 'local': 32, 'all': 32}}}
                                      },
        'Belkin Wemo switch': {'FS2': {'120': {'10': {'internet': 64, 'local': 64, 'all': 16}, '30': {'internet': 32, 'local': 32, 'all': 32}, '60': {'internet': 128, 'local': 128, 'all':16}},
                                       '240': {'10': {'internet': 32, 'local': 32, 'all': 32}, '30': {'internet': 32, 'local': 32, 'all': 32}, '60': {'internet': 32, 'local': 32, 'all':32}}}, #240 local can be 64
                               'FS3':{'120': {'10': {'internet': 64, 'local': 64, 'all': 64}, '30': {'internet': 32, 'local': 32, 'all': 64}, '60': {'internet': 128, 'local': 128, 'all':64}},
                                       '240': {'10': {'internet': 32, 'local': 32, 'all': 32}, '30': {'internet': 32, 'local': 32, 'all': 32}, '60': {'internet': 32, 'local': 32, 'all':32}}}},
        'Light Bulbs LiFX Smart Bulb': {'FS2': {'120': {'10': {'internet': 32, 'local': 32, 'all':32}, '30': {'internet': 32, 'local': 64, 'all':32}, '60': {'internet': 32, 'local': 64, 'all':32}},
                                                '240': {'10': {'internet': 32, 'local': 64, 'all':32}, '30': {'internet': 64, 'local': 64, 'all':32}, '60': {'internet': 64, 'local': 64, 'all':32}}},
                                        'FS3': {'120': {'10': {'internet': 64, 'local': 64, 'all': 64}, '30': {'internet': 32, 'local': 32, 'all': 64},'60': {'internet': 128, 'local': 128, 'all': 64 }},
                                                '240': {'10': {'internet': 32, 'local': 32, 'all': 64}, '30': {'internet': 32, 'local': 32, 'all': 64}, '60': {'internet': 32, 'local': 32, 'all': 64}}}
                                        },
        'Netatmo Welcom': {'FS2': {'120': {'10': {'internet': 32, 'local': 32, 'all': 32}, '30': {'internet': 32, 'local': 32, 'all':64}, '60': {'internet': 32, 'local': 32, 'all':64}},
                                   '240': {'10': {'internet': 32, 'local': 32,'all': 32}, '30': {'internet': 32, 'local': 32,'all': 32}, '60': {'internet': 32, 'local': 32, 'all': 32}}},
                           'FS3': {'120': {'10': {'internet': 32, 'local': 32, 'all': 128}, '30': {'internet': 32, 'local': 32, 'all': 128}, '60': {'internet': 32, 'local': 32, 'all': 128}},
                                   '240': {'10': {'internet': 32, 'local': 32, 'all': 64}, '30': {'internet': 32, 'local': 32, 'all': 64}, '60': {'internet': 32, 'local': 32, 'all': 128}}
                           }},
        'Samsung SmartCam': {'FS2': {'120': {'10': {'internet': 32, 'local': 32, 'all': 128}, '30': {'internet': 32, 'local': 32, 'all': 48}, '60': {'internet': 32, 'local': 32, 'all': 32}},
                                     '240': {'10': {'internet': 32, 'local': 32, 'all': 32}, '30': {'internet': 32, 'local': 32, 'all': 32}, '60': {'internet': 32, 'local': 32, 'all': 64}}},
                             'FS3': {'120': {'10': {'internet': 64, 'local': 64, 'all': 36}, '30': {'internet': 32, 'local': 32, 'all': 64}, '60': {'internet': 128, 'local': 128, 'all': 128}},
                                     '240': {'10': {'internet': 32, 'local': 32, 'all': 64}, '30': {'internet': 32, 'local': 32, 'all': 64}, '60': {'internet': 32, 'local': 32, 'all': 64}}}
                             },
        'TP-Link Smart plug': {'FS2': {'120': {'10': {'internet': 32, 'local': 32, 'all': 32}, '30': {'internet': 32, 'local': 32, 'all': 32},'60': {'internet': 32, 'local': 32,'all': 32}},
                                       '240': {'10': {'internet': 32, 'local': 32,'all': 32}, '30': {'internet': 32, 'local': 32,'all': 32}, '60': {'internet': 32, 'local': 32,'all': 32}}},
                               'FS3': {'120': {'10': {'internet': 64, 'local': 64, 'all': 64},'30': {'internet': 32, 'local': 32, 'all': 64}, '60': {'internet': 128, 'local': 128, 'all': 64}},
                                       '240': {'10': {'internet': 32, 'local': 32, 'all': 64}, '30': {'internet': 32, 'local': 32, 'all': 64}, '60': {'internet': 32, 'local': 32, 'all': 64}}}
                              },
        'Huebulb': {'FS2': {'120': {'10': {'internet': 32, 'local': 32, 'all': 36}, '30': {'internet': 32, 'local': 32,'all': 36},'60': {'internet': 32, 'local': 32, 'all': 36}},
                            '240': {'10': {'internet': 32, 'local': 32, 'all': 36}, '30': {'internet': 32, 'local': 32, 'all': 36}, '60': {'internet': 32, 'local': 32, 'all': 36}}}},
        "iHome": {'FS2': {'120': {'10': {'internet': 32, 'local': 32,'all': 36}, '30': {'internet': 32, 'local': 32,'all': 36},'60': {'internet': 32, 'local': 32,'all': 36}},
                          '240': {'10': {'internet': 32, 'local': 32, 'all': 36}, '30': {'internet': 32, 'local': 32,'all': 36}, '60': {'internet': 32, 'local': 32,'all': 36}}},
                  'FS3': {'120': {'10': {'internet': 64, 'local': 64, 'all': 36}, '30': {'internet': 32, 'local': 32, 'all': 64}, '60': {'internet': 128, 'local': 128, 'all': 64}},
                          '240': {'10': {'internet': 32, 'local': 32, 'all': 64}, '30': {'internet': 32, 'local': 32, 'all': 64}, '60': {'internet': 32, 'local': 32, 'all': 64}}}
                  }
    }

    return device_cluster[device][feature_set][time_window][s_rate][location]

def get_ax():
    fig = plt.figure()
    ax = fig.add_subplot(1, 1, 1)
    return ax

def get_reorganised_command_traffic_dict(iot_objects):
    commands = ["on", "off", "move", "brightness", "power", "color", "watch", "recording", "set", "photo"]
    locations = ["lan", "wan"]
    event_dict = {command: {location: [] for location in locations} for command in commands}
    for command_name in iot_objects:
        if "android" in command_name:
            # Match the command name, location and controller to get keys for storing in command_stats dict
            for name in commands:
                if name in command_name:
                    command = name
            for loc in locations:
                if re.search(loc, str(command_name)):
                    location = loc
            for device_obj in iot_objects[command_name]:
                event_dict[command][location].append(device_obj)

    return event_dict

def logged(func):
    def wrapper(*args, **kwargs):
        try:
            logging.info("funciton '{0}', info: {1} and {2}".format(func.__name__, args, kwargs))
            return func(*args, **kwargs)
        except Exception as e:
            logging.exception(e)
    return wrapper

def get_sampling_rate(*time_scale):
    """Return the sampling rate/s for a time scale/window"""
    time_scale_sampling_rate = {
        60: [60],
        120: [10,30,60],
        240: [10, 30, 60],
    }
    if time_scale:
        return time_scale_sampling_rate[time_scale[0]]
    else:
        return time_scale_sampling_rate


def log(type, pkt_ordinal, pkt_time, *len):
    if type == "pkt_len":
        logging.info("packet greater than 1500 bytes; ordinal:{0}, timestamp:{1}, ip pkt size: {2}".format(pkt_ordinal, pkt_time, len))
    elif type == "tls_handshake":
        logging.info("tls handshake pkt; ordinal:{0}".format(pkt_ordinal))

def get_mac_addr(device_name):

    iot_devices = {"Smart Things": "d0:52:a8:00:67:5e",
                    "Amazon Echo": "44:65:0d:56:cc:d3",
                    "Netatmo Welcom": "70:ee:50:18:34:43",
                    "TP-Link Day Night Cloud camera": "f4:f2:6d:93:51:f1",
                    "Samsung SmartCam": "00:16:6c:ab:6b:88",
                    "Dropcam": "30:8c:fb:2f:e4:b2",
                    "Insteon Camera": "00:62:6e:51:27:2e",
                    "Withings Smart Baby Monitor": "00:24:e4:11:18:a8",
                    "Belkin Wemo switch": "ec:1a:59:79:f4:89",
                    "TP-Link Smart plug": "50:c7:bf:00:56:39",
                    "iHome": "74:c6:3b:29:d7:1d",
                    "Belkin wemo motion sensor": "ec:1a:59:83:28:11",
                    "NEST Protect smoke alarm": "18:b4:30:25:be:e4",
                    "Netatmo weather station": "70:ee:50:03:b8:ac",
                    "Withings Smart scale": "00:24:e4:1b:6f:96",
                    "Blipcare Blood Pressure meter": "74:6a:89:00:2e:25",
                    "Withings Aura smart sleep sensor": "00:24:e4:20:28:c6",
                    "Light Bulbs LiFX Smart Bulb": "d0:73:d5:01:83:08",
                    "Triby Speaker": "18:b7:9e:02:20:44",
                    "PIX-STAR Photo-frame": "e0:76:d0:33:bb:85",
                    "HP Printer": "70:5a:0f:e4:9b:c0",
                    "Samsung Galaxy Tab": "08:21:ef:3b:fc:e3",
                    "Nest Dropcam": "30:8c:fb:b6:ea:45",
                    "Huebulb": "00:17:88:2b:9a:25"
                    }

    return iot_devices[device_name]

def get_iot_devices(country):
    """Returns a dictionary of IoT devices and their MAC address accroding to the folder in the Northeastern IMC 2019 Dataset.
    The addresses were obtained from manual wireshark inspection """
    uk_wired = ["bosiwo-camera-wired", "wansview-cam-wired"]
    uk_iot_devices = {
        "tplink-plug": "50:c7:bf:b1:d2:78",
        # "bosiwo-camera-wired":"ae:ca:06:0e:ec:89",
        "blink-camera":"f4:b8:5e:68:8f:35",
        # "charger-camera":"fc:ee:e6:2e:23:a3",
        "honeywell-thermostat": "b8:2c:a0:28:3e:6b",
        "magichome-strip": "dc:4f:22:89:fc:e7",
        "nest-tstat": "64:16:66:2a:98:62",
        "ring-doorbell": "f0:45:da:36:e6:23",
        "sengled-hub": "b0:ce:18:20:43:bf",
        "tplink-bulb":"50:c7:bf:ca:3f:9d",
        "t-wemo-plug":"58:ef:68:99:7d:ed",
        "wansview-cam-wired":"78:a5:dd:28:a1:b7",
        "yi-camera": "0c:8c:24:0b:be:fb",
    }
    us_iot_devices = {
        "phillips-bulb": "34:ce:00:99:9b:83",
        "tplink-plug":"50:c7:bf:5a:2e:a0",
        "tplink-bulb": "50:c7:bf:a0:f3:76",
        "t-phillips-hub": "00:17:88:68:5f:61",
        "zmodo-doorbell":"7c:c7:09:56:6e:48",
    }
    if country == "uk":
        return uk_iot_devices
    elif country == "us":
        return us_iot_devices

def get_iot_device_name(mac_addr):
    """Takes in mac address and returns device name"""
    iot_devices = {"Smart Things": "d0:52:a8:00:67:5e",
                        "Amazon Echo": "44:65:0d:56:cc:d3",
                        "Netatmo Welcom": "70:ee:50:18:34:43",
                        "TP-Link Day Night Cloud camera": "f4:f2:6d:93:51:f1",
                        "Samsung SmartCam": "00:16:6c:ab:6b:88",
                        "Dropcam": "30:8c:fb:2f:e4:b2",
                        "Insteon Camera": "00:62:6e:51:27:2e",
                        "Withings Smart Baby Monitor": "00:24:e4:11:18:a8",
                        "Belkin Wemo switch": "ec:1a:59:79:f4:89",
                        "TP-Link Smart plug": "50:c7:bf:00:56:39",
                        "iHome": "74:c6:3b:29:d7:1d",
                        "Belkin wemo motion sensor": "ec:1a:59:83:28:11",
                        "NEST Protect smoke alarm": "18:b4:30:25:be:e4",
                        "Netatmo weather station": "70:ee:50:03:b8:ac",
                        "Withings Smart scale": "00:24:e4:1b:6f:96",
                        "Blipcare Blood Pressure meter": "74:6a:89:00:2e:25",
                        "Withings Aura smart sleep sensor": "00:24:e4:20:28:c6",
                        "Light Bulbs LiFX Smart Bulb": "d0:73:d5:01:83:08",
                        "Triby Speaker": "18:b7:9e:02:20:44",
                        "PIX-STAR Photo-frame": "e0:76:d0:33:bb:85",
                        "HP Printer": "70:5a:0f:e4:9b:c0",
                        "Samsung Galaxy Tab": "08:21:ef:3b:fc:e3",
                        "Huebulb": "00:17:88:2b:9a:25",
                        "Chromecast": "f4:f5:d8:8f:0a:3c",
                        "Nest Dropcam": "30:8c:fb:b6:ea:45",
                        }
    for item in iot_devices.items():
        if mac_addr in item:
            return item[0]


def ihome_first_pkt_ordinal(file):
    d = {'18-06-01.pcap': 358, '18-06-02.pcap': 311, '18-06-03.pcap': 2546, '18-06-04.pcap': 1538, '18-06-05.pcap': 260,
     '18-06-06.pcap': 2661, '18-06-07.pcap': 1579, '18-06-08.pcap': 318, '18-06-20.pcap': 1235,
     '18-10-22.pcap': 1612615, '18-10-23.pcap': 945, '18-10-24.pcap': 668, '18-10-25.pcap': 423, '18-10-26.pcap': 3,
     '18-10-27.pcap': 227}

    ordinal_epoch = {
        1612615: 1540182621.644376000,
    }

    return ordinal_epoch[d[file]]

def attack_flow_id():
    attack_flows = {
        '18-06-05': {
            'TP-Link Smart plug': [],
            'Samsung SmartCam':[('191.168.1.248', '149.171.36.239', '5222', '49152', "TCP"),]
        },

    }

def attack_ordinals(device):
    d = {'Light Bulbs LiFX Smart Bulb': {
        '18-10-23': [(482650, 498352), (523518, 542777), (565200, 589345), (847094, 861646), (1066551, 1083680), (1108066, 1128057),
                     (1243449, 1258990), (1282312, 1304485), (1328704, 1357843), (1906842, 1923975), (1946484, 1976280), (1999654, 2051308)],
        '18-10-24': [(17334,32188), (32682,51256), (51420, 70302)]
    }}
    return d[device]

def get_lifx_annotations():
    rel_attack_time = {'18-10-23': [(16221.548086, 16821.86568), (17828.080217, 18428.032069), (19436.090016, 20036.036149), (31009.442249, 31606.617522), (39407.077718, 40005.309043), (41022.43378, 41622.190927999996)], '18-10-24': [(675.449124, 1266.321328), (1277.437605, 1877.361357), (1887.5936199999999, 2487.5092360000003)]}
    rel_attack_type = {(16221.548086, 16821.86568):{'attack_type':'ARPSpoof1L2D'}, (17828.080217, 18428.032069): {'attack_type':'ARPSpoof10L2D'}, (19436.090016, 20036.036149): {'attack_type':'ARPSpoof100L2D'}, (31009.442249, 31606.617522): {'attack_type':'UDPDevice1L2D'}, (39407.077718, 40005.309043): {'attack_type':'UDPDevice10L2D'},
                       (41022.43378, 41622.190927999996): {'attack_type':'UDPDevice100L2D'}, (675.449124, 1266.321328):{'attack_type':'UDPDevice1W2D'}, (1277.437605, 1877.361357): {'attack_type':'UDPDevice10W2D'}, (1887.5936199999999, 2487.5092360000003): {'attack_type':'UDPDevice100W2D'}}

    return rel_attack_time, rel_attack_type


def tp_benign_plot():
    fs2_2min_10 = [97.35957753, 97.22279793, 97.72809232, 90.88891131, 98.13384168]
    fs2_2min_30 = [92.94512878, 97.03749741, 83.62162162, 87.9072113, 97.70310933]
    fs2_2min_60 = [97.40924356, 96.90315898, 96.37903081, 88.39177751, 96.03930613]
    fs2_4min_10 = [90.50064185, 97.45130543, 96.96422118, 83.48512447, 94.15192926]
    fs2_4min_30 = [89.53786906, 96.83164216, 95.34464092, 87.64158576, 97.16753716]
    fs2_4min_60 = [89.34873276, 94.42948851, 97.07792208, 88.35049465, 97.30977715]
    fs3_2min_10 = [95.55128821, 95.32642487, 98.1067436, 96.1154273, 97.89304706]
    fs3_2min_30 = [94.4968805, 95.2765693, 95.42342342, 95.94553707, 93.76128385]
    fs3_2min_60 = [95.1383336, 95.2765693, 97.89227166, 90.5280129, 97.02195929]
    fs3_4min_10 = [93.93453145, 94.59179445, 85.79689194, 87.26978344, 92.56430868]
    fs3_4min_30 = [88.18998716, 96.00331332, 94.4063515, 92.69822006, 96.14302933]
    fs3_4min_60 = [92.33237087, 95.63056533, 94.62481962, 93.78154654, 96.2256575]
    x = [10, 30, 60]
    print('test')
    fs2_2min_samples = [fs2_2min_10, fs2_2min_30, fs2_2min_60]
    fs2_4min_samples = [fs2_4min_10, fs2_4min_30, fs2_4min_60]
    fs3_2min_samples = [fs3_2min_10, fs3_2min_30, fs3_2min_60]
    fs3_4min_samples = [fs3_4min_10, fs3_4min_30, fs3_4min_60]
    fs2_2min = [sum(l) / len(l) for l in fs2_2min_samples]
    fs2_4min = [sum(i) / len(i) for i in fs2_4min_samples]
    fs3_2min = [sum(i) / len(i) for i in fs3_2min_samples]
    fs3_4min = [sum(i) / len(i) for i in fs3_4min_samples]
    fig = plt.figure()
    ax = fig.add_subplot(1, 1, 1)
    # ax.plot(x, fs2_2min, marker="^", label='FS1', color='r')
    # ax.plot(x, fs2_4min, marker="x", label='FS2', color='b')
    # ax.plot(x, fs3_2min, marker="o", label="FS3", color='g')
    # ax.plot(x, fs3_4min, marker="+", label="FS4", color='c')
    ax.set_ylim([90,100])
    def subcategorybar(X, vals, width=0.8):
        import numpy as np
        label = ['FS1', 'FS2', 'FS3', 'FS4']
        n = len(vals)
        _X = np.arange(len(X))
        for i in range(n):
            ax.bar(_X - width / 2. + i / float(n) * width, vals[i],
                    width=width / float(n), align="edge", label=label[i])
        plt.xticks(_X, X)

    subcategorybar(x, [fs2_2min,fs2_4min, fs3_2min,fs3_4min])
    for item in ([ax.title, ax.xaxis.label, ax.yaxis.label] +
                 ax.get_xticklabels() + ax.get_yticklabels()):
        item.set_fontsize(16)
    for item in ([ax.title, ax.xaxis.label, ax.yaxis.label] +
                 ax.get_xticklabels() + ax.get_yticklabels()):
        item.set_fontsize(20)
    ax.set_xlabel("Sampling rate (time/seconds)")
    ax.set_ylabel("TPR (%)")
    plt.legend(loc='best', fontsize=14)
    plt.show()
    plt.savefig("sampling_rate_tpr.png")

def fs_fpr_plot():
    fs2_2min_10 = [1.855137925, 2.686443315, 1.382823872, 8.585346052, 1.361436063]
    fs2_2min_30 = [6.260083898, 2.871954381, 15.84768812, 11.3416743, 1.794535739]
    fs2_2min_60 = [1.837228042, 2.996371177, 2.850917015, 10.81740545, 3.350151362]
    fs2_4min_10 = [8.530651962, 2.40713841, 1.685599121, 15.55783009, 5.181137422]
    fs2_4min_30 = [9.474367294, 3.088082902, 3.365032919, 11.17261173, 2.104837078]
    fs2_4min_60 = [9.753726507, 5.492227979, 1.752464403, 10.63916684, 1.862725248]
    fs3_2min_10 = [3.84863124, 4.574688797, 0.8925318761, 1.613391147]
    fs3_2min_30 = [4.756530152, 4.634525661, 3.831487198, 3.234665853, 5.766129032]
    fs3_2min_60 = [4.172036082, 4.634525661, 1.2, 8.680626144, 2.331684667]
    fs3_4min_10 = [4.843953186, 5.270803071, 13.42086069, 11.71171171, 6.761133603]
    fs3_4min_30 = [10.86603957, 3.917098446, 4.560379424, 6.124539123, 3.137016798]
    fs3_4min_60 = [6.830689544, 4.29015544, 4.514015289, 5.107252298, 2.956063981]
    x = [10,30,60]
    fs2_2min_samples = [fs2_2min_10, fs2_2min_30,fs2_2min_60]
    fs2_4min_samples = [fs2_4min_10, fs2_4min_30, fs2_4min_60]
    fs3_2min_samples = [fs3_2min_10, fs3_2min_30, fs3_2min_60]
    fs3_4min_samples = [fs3_4min_10, fs3_4min_30, fs3_4min_60]
    fs2_2min = [sum(l)/len(l) for l in fs2_2min_samples]
    fs2_4min = [sum(i)/len(i) for i in fs2_4min_samples]
    fs3_2min = [sum(i) / len(i) for i in fs3_2min_samples]
    fs3_4min = [sum(i) / len(i) for i in fs3_4min_samples]
    fig = plt.figure()
    ax = fig.add_subplot(1, 1, 1)
    # ax.plot(x, fs2_2min,marker="^",label='FS1', color='r')
    # ax.plot(x, fs2_4min, marker="x", label='FS2', color='b')
    # ax.plot(x, fs3_2min, marker="o", label="FS3", color='g')
    # ax.plot(x, fs3_4min, marker="+", label="FS4", color='c')



    def subcategorybar(X, vals, width=0.8):
        import numpy as np
        label = ['FS1', 'FS2', 'FS3', 'FS4']
        n = len(vals)
        _X = np.arange(len(X))
        for i in range(n):
            ax.bar(_X - width / 2. + i / float(n) * width, vals[i],
                    width=width / float(n), align="edge", label=label[i])
        plt.xticks(_X, X)

    subcategorybar(x, [fs2_2min,fs2_4min, fs3_2min,fs3_4min])
    for item in ([ax.title, ax.xaxis.label, ax.yaxis.label] +
                 ax.get_xticklabels() + ax.get_yticklabels()):
        item.set_fontsize(16)

    # ax.set_title("Feature Set FPR")
    ax.set_xlabel("Sampling rate (time/seconds)")
    ax.set_ylabel("FPR (%)")
    plt.legend(loc='best', fontsize=12)
    plt.show()
    plt.savefig("sampling_rate_fpr.png")


def get_device_type(device, *keys):
    device_types = {
        'lighting':['Light Bulbs LiFX Smart Bulb', 'Huebulb'],
        'camera':['Samsung SmartCam', 'Netatmo Welcom'],
        'sensor':['Belkin wemo motion sensor'],
        'switch': ['iHome', 'Belkin Wemo switch', 'TP-Link Smart plug']
    }
    if keys:
        return list(device_types.keys())
    else:
        for type in device_types:
            if device in device_types[type]:
                return type
            else:
                for d_name in device_types[type]:
                    if d_name in device:
                        return type

def sampling_rate_detection():
    device_type_accuracy = { 'camera': {
            'accuracy': {
                10: [97.2464, 96.5349483717236],
                30: [89.7709110282365, 96.3692430120362],
                60: [97.4742084667378, 94.4212410501193]
            },
            'fpr': {
                10: [2.28384991843393, 2.93371231347071],
                30: [9.87497735096938, 2.86818551668022],
                60: [1.83303085299455, 4.799186578546]
            },
            'avg_detection_rate': {
                10: [79.1111111111111, 71.3468013468013],
                30: [77.7777777777777, 63.6195286195286],
                60: [72.1313131313131, 62.3484848484848]
            }
        },

    }
s = {'accuracy': {'10': [97.799588412221, 96.6449207828518, 98.44915001491201], '30': [97.71971496437055, 96.02525618465995, 97.86324786324785], '60': [97.48417721518987, 97.27799627406334, 98.03980099502488]},
     'fpr': {'10': [1.3561511139812723, 3.2572614107883817, 1.0588947156111337], '30': [1.3727390180878551, 3.878058896723352, 1.6533924790805523], '60': [1.6620945618847829, 2.623120787973043, 1.3222973654991421]},
        'avg_detection_rate': {'10': [56.094276094276104, 44.444444444444436, 68.94736842105263], '30': [55.82491582491582, 44.444444444444436, 68.94736842105263], '60': [55.993265993266, 44.444444444444436, 60.96491228070176]}}


def get_s(file_name):
    rates = ['10', '30', '60']
    for s in rates:
        if s in file_name:
            return s

def plot_sampling_impact(plot_type, model_data, y_label):
    x = ['10', '30', '60']
    device_types = get_device_type('iHome', True)
    device_type_avg = {i: {j: None for j in x } for i in device_types}
    fig = plt.figure()
    ax = fig.add_subplot(1, 1, 1)
    for item in ([ax.title, ax.xaxis.label, ax.yaxis.label] +
                 ax.get_xticklabels() + ax.get_yticklabels()):
        item.set_fontsize(15)

    for device_type in model_data:
        if device_type == 'sensor':
            continue
        for s in model_data[device_type][plot_type]:
            data = model_data[device_type][plot_type][s]
            device_type_avg[device_type][s] = sum(data) / len(data)

    l = []
    print(l)
    p = []
    for d in device_type_avg:
        if d == "sensor":
            continue
        # ax.plot(x, list(device_type_avg[d].values()), label=d)
        l.append(d)
        p.append(list(device_type_avg[d].values()))

    def subcategorybar(X, vals, width=0.8):
        import numpy as np
        # label = ['lighting', 'FS2', 'FS3', 'FS4']
        n = len(vals)
        _X = np.arange(len(X))
        for i in range(n):
            ax.bar(_X - width / 2. + i / float(n) * width, vals[i],
                    width=width / float(n), align="edge", label=l[i])
        plt.xticks(_X, X)

    subcategorybar(x, p)
    if plot_type == 'accuracy':
        ax.set_ylim([90,100])
    if plot_type == 'avg_detection_rate':
        ax.set_ylim([50,100])
    ax.set_ylabel(y_label)
    ax.set_xlabel("Sampling rate (time/seconds)")
    plt.legend(loc='best', fontsize=13)
    plt.savefig(plot_type+"sampling_impact.png")
    plt.show()


def get_infected_devices():
    inf_devices = {'TP-Link Smart plug': '50:c7:bf:00:56:39',
                   'Netatmo Welcom': '70:ee:50:18:34:43',
                   'Huebulb': '00:17:88:2b:9a:25',
                   'iHome': '74:c6:3b:29:d7:1d',
                   'Belkin Wemo switch': 'ec:1a:59:79:f4:89',
                   'Belkin wemo motion sensor': 'ec:1a:59:83:28:11',
                   'Samsung SmartCam': '00:16:6c:ab:6b:88',
                   'Light Bulbs LiFX Smart Bulb': 'd0:73:d5:01:83:08'}
    return inf_devices


def stretch_xaxis(p):
    p.rcParams["figure.figsize"] = [20, 3.50]
    p.rcParams["figure.autolayout"] = True

def get_graph_save_folder(device_name):
    save_path = Path(r"C:\Users\amith\Documents\Uni\Masters\Graphs\flow_tp") / device_name
    return save_path

def get_attack_window_timestamps(device):
    timestamps = {
        'Netatmo Welcom': {
            '18-06-01':
                {
                'local_inputs': {'1pps': [(62900, 63720)], '10pps': [(64440, 65280)], '100pps': [(66210, 66840)]},
                'local_outputs': {'1pps': [(62900, 63720)], '10pps': [(64440, 65280)], '100pps': [(66210, 66840)]},
                'internet_inputs': {'1pps': [(47160, 48120)], '10pps': [(48840, 49680)], '100pps': [(50400, 51240)]},
                'internet_outputs': {'1pps': [(47160, 48120)], '10pps': [(48840, 49680)], '100pps': [(50400, 51360)]}
                },
        },
        'Samsung SmartCam': {
            '18-06-01':
                {
                    'local_inputs': {'1pps': [(53260, 54000)], '10pps': [(54840, 55680)], '100pps': [(56400, 57360)]},
                    'local_outputs': {'1pps': [(53260, 54000)], '10pps': [(54840, 55680)], '100pps': [(56400, 57360)]},
                    'internet_inputs': {'1pps': [(37500, 38400), (53160, 54120)], '10pps': [(39120, 39960), (54840, 55680)], '100pps': [(40800, 41640), (56400, 57240)]},
                    'internet_outputs': {'1pps': [(37500, 38400), (53160, 54120)], '10pps': [(39060, 39960), (54840, 55680)], '100pps': [(40800, 41640), (56400, 57240)]},
                },
        },
        'TP-Link Smart plug': {
            '18-06-01':
                {
                    'local_inputs': {'1pps': [(53400, 54000)], '10pps': [(54900, 55500)], '100pps': [(56600, 57200)]},
                    'local_outputs': {'1pps': [(53400, 54000)], '10pps': [(54900, 55500)], '100pps': [(56600, 57200)]},
                    'internet_inputs': {'1pps': [(37500, 38100), (53400, 54000)], '10pps': [(39300, 39900), (54900, 55500)], '100pps': [(41000, 41600), (56600, 57200)]},
                    'internet_outputs': {'1pps': [(37500, 38100), (53400, 54000)], '10pps': [(39300, 39900), (54900, 55500)], '100pps': [(41000, 41600), (56600, 57200)]},
                },
        }

    }

    return timestamps[device]

def yield_pcap(data_path):
    """This function is for refactoring data set file traversals i.e., yield next pcap in dataset"""
    pass



def get_all_attack_epochs(device_attacks_objects):
    """This function takes in all Attack objects and returns a list of tuples of all attack epochs (start_epoch, end_epoch) for each date"""
    pcap_epochs = {}
    for DeviceAttacks in device_attacks_objects:
        device_attack_epochs = DeviceAttacks.attack_epochs
        pcap_epochs.update(device_attack_epochs)
    return pcap_epochs

def get_start_epoch_device_object(start_epoch, device_attacks_objects):
    for DeviceAttack in device_attacks_objects:
        epoch_timestamps = list(DeviceAttack.attack_epochs.keys())
        if start_epoch in epoch_timestamps:
            return DeviceAttack

def get_epoch_attack_desc(deviceAttack, epoch_timestamp):
    return deviceAttack.attack_epoch_attack_desc[epoch_timestamp]


def get_attack_pkt_ordinal_window(attack_data_path, device_attacks_objects):
    """TODO: Refactor the directory file loop + REFACTOR THIS WHOLE FUNCTION"""
    from scapy.all import RawPcapReader, RawPcapNgReader
    from AttackTimeStamp import AttackTimestamp
    from scapy.layers.l2 import Ether
    from io import FileIO

    def typeCast(epoch):
        return int(str(epoch)[:10])

    device_discard_list = ["Light Bulbs LiFX Smart Bulb", "Huebulb"]
    infected_devices = get_infected_devices()
    relevant_addresses = []
    all_attacks_epoch_timestamps = get_all_attack_epochs(device_attacks_objects)
    all_timestamp_objects = []
    print(all_attacks_epoch_timestamps)
    for i in infected_devices:
        if i not in device_discard_list:
            relevant_addresses.append(infected_devices[i])
    files = []
    start_epochs = list(all_attacks_epoch_timestamps.keys())
    end_epochs = list(all_attacks_epoch_timestamps.values())
    attack_ordinal_window = {}

    """Loop through dataset"""
    limit = 2
    print('min epoch', min(start_epochs))
    for file in attack_data_path.iterdir():
        count = 0
        if file.name == '18-06-01.pcap':
            limit = math.inf
        date = file.name[:-5]
        files.append(date)
        attack_ordinal_window[date] = {}
        active_attack_timestamp = None
        is_attack_window_initiated = False
        print('file', file.name)
        for pkt_data, pkt_metadata in RawPcapReader(FileIO(file)):
            count += 1
            if count < limit:
                ether_pkt = Ether(pkt_data)
                # if ether_pkt.src in relevant_addresses or ether_pkt.dst in relevant_addresses:
                try:
                    # test the packet metadata tuple to figure out which tuple type is in the pcap
                    pkt_metadata.tshigh
                    tuple_type = "tshigh"
                except AttributeError:
                    tuple_type = "seconds",
                if tuple_type == "tshigh":
                    pkt_epoch_timestamp = typeCast((pkt_metadata.tshigh << 32) | pkt_metadata.tslow)
                elif tuple_type == "seconds":
                    print('seconds technique')
                    pkt_epoch_timestamp = typeCast(pkt_metadata.sec + (pkt_metadata.usec / 1000000))

                # print(file.name, pkt_epoch_timestamp)

                if pkt_epoch_timestamp in start_epochs:
                    # print(pkt_epoch_timestamp, start_epochs.index(pkt_epoch_timestamp))
                    try:
                        assert start_epochs.index(pkt_epoch_timestamp) >= 0
                    except AssertionError as e:
                        print("ASSERTION ERROR ON START EPOCH")
                        continue
                    # Get device of timestamp
                    pkt_mac_addrs = [ether_pkt.src, ether_pkt.dst]
                    deviceAttack = get_start_epoch_device_object(pkt_epoch_timestamp, device_attacks_objects)
                    if deviceAttack.device_addr not in pkt_mac_addrs:
                        print("wrong packet")
                        continue
                    end_epoch = all_attacks_epoch_timestamps[pkt_epoch_timestamp]
                    attack_epoch_timestamp = (pkt_epoch_timestamp, end_epoch) # (start, end)

                    # DEBUGGING MAY REQUIRE A CHECK TO SEE IF PREV ATTACK WINDOW COMPUTE IS FINISHED
                    if active_attack_timestamp is not None:
                        if active_attack_timestamp.ordinal_window_state != "end_found":
                            print("ANOTHER START FOUND BEFORE END OF PREV")
                    if attack_epoch_timestamp in attack_ordinal_window[date]:
                        """TODO: This is not optimal solution design. Refactor to use a boolean for better reliability and readability"""
                        """Means attack window is initiated. Assert to make sure). If initiated, increment ordinal window"""
                        assert active_attack_timestamp.ordinal_window_state == "start_found"
                        active_attack_timestamp.incrementEndOrdinal()
                    else:
                        attack_ordinal_window[date][attack_epoch_timestamp] = (count, count)
                        TimeStamp = AttackTimestamp(pkt_epoch_timestamp, end_epoch, count)
                        TimeStamp.set_start_found_state()
                        print("attack is", get_epoch_attack_desc(deviceAttack, attack_epoch_timestamp), deviceAttack.device_name)
                        all_timestamp_objects.append(TimeStamp)
                        active_attack_timestamp = TimeStamp
                else:
                    """Either inside attack window or not"""
                    # Check to avoid referencing errors
                    if active_attack_timestamp is not None:
                        if pkt_epoch_timestamp == active_attack_timestamp.end_epoch:
                            print("end_found")
                        if active_attack_timestamp.is_end_epoch(pkt_epoch_timestamp):
                            active_attack_timestamp.set_end_found_state()
                            print("end found")
                            active_attack_timestamp.set_test_window(count)
                            attack_ordinal_window[date][attack_epoch_timestamp] = active_attack_timestamp.ordinal_window
                        elif active_attack_timestamp.is_start_found():
                            active_attack_timestamp.incrementEndOrdinal()
                        else:
                            continue
                    else:
                        continue
                # print(str(pkt_epoch_timestamp))
            else:
                # print('last packet epoch',(pkt_metadata.tshigh << 32) | pkt_metadata.tslow)
                break


    return ['test']

def get_all_attack_annotations():
    from attack_annotations import Attacks
    devices = get_all_devices()
    infected_devices = ["TP-Link Smart plug", "Netatmo Welcom", "Huebulb", "iHome", "Belkin Wemo switch",
                             "Belkin wemo motion sensor", "Samsung SmartCam", "Light Bulbs LiFX Smart Bulb"]
    all_annotations = [Attacks(devices[inf_d]) for inf_d in infected_devices]
    return all_annotations

def get_all_devices():
    return {"Smart Things": "d0:52:a8:00:67:5e",
                       "Amazon Echo": "44:65:0d:56:cc:d3",
                       "Netatmo Welcom": "70:ee:50:18:34:43",
                       "TP-Link Day Night Cloud camera": "f4:f2:6d:93:51:f1",
                       "Samsung SmartCam": "00:16:6c:ab:6b:88",
                       "Dropcam": "30:8c:fb:2f:e4:b2",
                       "Insteon Camera": "00:62:6e:51:27:2e",
                       "Withings Smart Baby Monitor": "00:24:e4:11:18:a8",
                       "Belkin Wemo switch":"ec:1a:59:79:f4:89",
                       "TP-Link Smart plug": "50:c7:bf:00:56:39",
                       "iHome":"74:c6:3b:29:d7:1d",
                       "Belkin wemo motion sensor": "ec:1a:59:83:28:11",
                       "NEST Protect smoke alarm":"18:b4:30:25:be:e4",
                       "Netatmo weather station":"70:ee:50:03:b8:ac",
                       "Withings Smart scale":"00:24:e4:1b:6f:96",
                       "Blipcare Blood Pressure meter":"74:6a:89:00:2e:25",
                       "Withings Aura smart sleep sensor":"00:24:e4:20:28:c6",
                       "Light Bulbs LiFX Smart Bulb":"d0:73:d5:01:83:08",
                       "Triby Speaker":"18:b7:9e:02:20:44",
                       "PIX-STAR Photo-frame":"e0:76:d0:33:bb:85",
                       "HP Printer":"70:5a:0f:e4:9b:c0",
                       "Samsung Galaxy Tab":"08:21:ef:3b:fc:e3",
                       "Huebulb": "00:17:88:2b:9a:25",
                       "Chromecast": "f4:f5:d8:8f:0a:3c",
                       "Nest Dropcam":"30:8c:fb:b6:ea:45",
                       }



def low_rate_attacks():
    all_devices = {
        'FS1':{
            'reflection':{
                'tcp': [],
                'ssdp':[],
                'snmp':[]
            },
            'direct':{
                'arp': [],
                'tcp':[],
                'fraggle':[]
            }
        },
        'FS2': {
            'reflection': {
                'tcp': [],
                'ssdp': [],
                'snmp': []
            },
            'direct': {
                'arp': [],
                'tcp': [],
                'fraggle': []
            }
        },
        'FS3': {
            'reflection': {
                'tcp': [],
                'ssdp': [],
                'snmp': []
            },
            'direct': {
                'arp': [],
                'tcp': [],
                'fraggle': []
            }
        },
        'FS4': {
            'reflection': {
                'tcp': [],
                'ssdp': [],
                'snmp': []
            },
            'direct': {
                'arp': [],
                'tcp': [],
                'fraggle': []
            }
        }
    }

    p = Path(r'C:\Users\amith\Documents\Uni\Masters\results')
    fs = ['FS2', "FS3"]
    window = ['120', '240']
    attack_types = ["TcpSynDevice1L2D", "TcpSynDevice1W2D"]

    import pandas as pd
    for device in p.iterdir():
        if "motion" in device.name:
            continue
        if 'device_type' in device.name:
            continue
        if 'Huebulb' in device.name:
            continue
        for f in device.iterdir():
            f_set = device /f
            for w in f_set.iterdir():
                results = w / "60"
                file = results/"detection_results.csv"
                try:
                    data = pd.read_csv(file, header=None)
                except FileNotFoundError:
                    continue
                if "FS2" in f.name:
                    if "120" in w.name:
                        fs_key = "FS1"
                    elif '240' in w.name:
                        fs_key = "FS2"
                elif "FS3" in f.name:
                    if "120" in w.name:
                        fs_key = "FS3"
                    elif "240" in w.name:
                        fs_key = "FS4"

                for index, row in data.iterrows():
                    if "Reflection" in row[0] and "100" in row[0]:
                        # print(row[0])
                        all_devices[fs_key]['reflection']['tcp'].append(row[3])
                    if "Udp" in row[0] and "100" in row[0]:
                        all_devices[fs_key]['direct']['fraggle'].append(row[3])
                    if "Snmp" in row[0] and "100" in row[0] :
                        all_devices[fs_key]['reflection']['snmp'].append(row[3])
                    if 'Arp' in row[0] and "100" in row[0]:
                        all_devices[fs_key]['direct']['arp'].append(row[3])
                    if "Tcp" in row[0] and "Device" in row[0] and "100" in row[0]:
                        all_devices[fs_key]['direct']['tcp'].append(row[3])
    import numpy as np
    out = {fs: {t: {attack: np.mean(all_devices[fs][t][attack]) for attack in all_devices[fs][t]} for t in all_devices[fs]} for fs in all_devices}
    print(out)
    


def plot_attack_rate(data, title):
    x = ['10', '30', '60']
    import numpy as np
    fig = plt.figure()
    ax = fig.add_subplot(1, 1, 1)
    
    ax.set_xlabel("Sampling rate (time/seconds)")
    t = [10, 30, 60]
    ax.plot(x, np.poly1d(np.polyfit(t, data['FS4'], 1))(np.unique(t)), label='FS1', color='b')
    ax.plot(x, np.poly1d(np.polyfit(t, data['FS2'], 1))(np.unique(t)), label='FS2', color='g')
    ax.plot(x, np.poly1d(np.polyfit(t, data['FS3'], 1))(np.unique(t)), label='FS3', color='r')
    ax.plot(x, np.poly1d(np.polyfit(t, data['FS1'], 1))(np.unique(t)), label='FS4', color='m')
    ax.set_ylabel("Detection rate (%)")
    ax.set_title(title)
    for item in [ax.title, ax.xaxis.label, ax.yaxis.label]:
        if item == ax.title:
            item.set_size(20)
        else:
            item.set_size(16.5)
    for label in ax.get_xticklabels() + ax.get_yticklabels():
        if title == 'High Rate Reflective Attacks':
            if label in ax.get_yticklabels():
                label.set_size(13.5)
            else:
                label.set_size(15.9)            
        else:
            label.set_fontsize(15.9)
    plt.legend(loc='best', fontsize=15)
    plt.show()
    plt.savefig(title+'.png')

def fs_sets_plots():
    first =  {'FS1': {'reflection': {'tcp': 64.54545454545455, 'ssdp': 40.8, 'snmp': 50.0}, 'direct': {'arp': 62.0, 'tcp': 65.05681818181819, 'fraggle': 90.0}},
              'FS2': {'reflection': {'tcp': 58.33333333333333, 'ssdp': 52.5, 'snmp': 44.444444444444436}, 'direct': {'arp': 33.33333333333333, 'tcp': 47.91666666666666, 'fraggle': 33.33333333333333}},
              'FS3': {'reflection': {'tcp': 62.36742424242425, 'ssdp': 54.5, 'snmp': 44.44444444444445}, 'direct': {'arp': 54.666666666666664, 'tcp': 60.227272727272734, 'fraggle': 90.0}},
              'FS4': {'reflection': {'tcp': 60.416666666666664, 'ssdp': 60, 'snmp': 44.444444444444436}, 'direct': {'arp': 39.99999999999999, 'tcp': 49.99999999999999, 'fraggle': 33.33333333333333}}}

    second = {'FS1': {'reflection': {'tcp': 65.58712121212122, 'ssdp': 35.7, 'snmp': 44.444444444444436}, 'direct': {'arp': 50.0, 'tcp': 61.51515151515152, 'fraggle': 70.0}},
              'FS2': {'reflection': {'tcp': 58.33333333333333, 'ssdp': 42.3, 'snmp': 44.444444444444436}, 'direct': {'arp': 39.99999999999999, 'tcp': 47.91666666666666, 'fraggle': 33.33333333333333}},
              'FS3': {'reflection': {'tcp': 61.93181818181818, 'ssdp': 45.6, 'snmp': 33.33333333333333}, 'direct': {'arp': 61.333333333333336, 'tcp': 60.96590909090909, 'fraggle': 70.0}},
              'FS4': {'reflection': {'tcp': 58.33333333333333, 'ssdp': 50.3, 'snmp': 33.33333333333333}, 'direct': {'arp': 39.99999999999999, 'tcp': 54.16666666666666, 'fraggle': 33.33333333333333}}}

    third = {'FS1': {'reflection': {'tcp': 64.01515151515152, 'ssdp': 30.5, 'snmp': 38.888888888888886}, 'direct': {'arp': 66.0, 'tcp': 62.026515151515156, 'fraggle': 70.0}},
             'FS2': {'reflection': {'tcp': 56.25, 'ssdp': 40.9, 'snmp': 33.33333333333333}, 'direct': {'arp': 53.33333333333333, 'tcp': 41.66666666666666, 'fraggle': 49.99999999999999}},
             'FS3': {'reflection': {'tcp': 64.01515151515152, 'ssdp': 45.6, 'snmp': 27.77777777777777}, 'direct': {'arp': 50.0, 'tcp': 54.659090909090914, 'fraggle': 90.0}},
             'FS4': {'reflection': {'tcp': 56.25, 'ssdp': 60.4, 'snmp': 33.33333333333333}, 'direct': {'arp': 60.0, 'tcp': 54.16666666666666, 'fraggle': 49.99999999999999}}}


    x = ['10', '30', '60']
    sets = ["FS1", "FS2", "FS3", "FS4"]
    s = [first, second, third]
    reflective_averages = {fs:[] for fs in sets}
    direct_averages = {fs:[] for fs in sets}
    import numpy as np
    for d in s:
        for fs in d:
            vals = list(d[fs]['reflection'].values())
            reflective_averages[fs].append(np.mean(vals))
            direct_averages[fs].append(np.mean(list(d[fs]['direct'].values())))

    # print(direct_averages)
    print(reflective_averages)
    plot_attack_rate(reflective_averages, "Low Rate Reflective Attacks")
    plot_attack_rate(direct_averages,"Low Rate Direct Attacks")


def fs_medium_rate():
    first = {'FS1': {'reflection': {'tcp': 82.5, 'ssdp': 90, 'snmp': 93.33333333333333}, 'direct': {'arp': 82.0, 'tcp': 72.4621212121212, 'fraggle': 90.0}},
             'FS2': {'reflection': {'tcp': 54.166666666666664, 'ssdp': 65, 'snmp': 66.66666666666666}, 'direct': {'arp': 60.0, 'tcp': 60.416666666666664, 'fraggle': 66.66666666666666}},
             'FS3': {'reflection': {'tcp': 92.5, 'ssdp': 75.6, 'snmp': 86.66666666666667}, 'direct': {'arp': 79.33333333333333, 'tcp': 86.09848484848484, 'fraggle': 90.0}},
             'FS4': {'reflection': {'tcp': 64.58333333333333, 'ssdp': 55, 'snmp': 44.444444444444436}, 'direct': {'arp': 60.0, 'tcp': 70.83333333333333, 'fraggle': 66.66666666666666}}}


    second = {'FS1': {'reflection': {'tcp': 83.75, 'ssdp': 81, 'snmp': 86.66666666666667}, 'direct': {'arp': 86.0, 'tcp': 80.30303030303031, 'fraggle': 70.0}},
              'FS2': {'reflection': {'tcp': 58.33333333333333, 'ssdp': 53, 'snmp': 55.55555555555554}, 'direct': {'arp': 66.66666666666666, 'tcp': 64.58333333333333, 'fraggle': 66.66666666666666}},
              'FS3': {'reflection': {'tcp': 85.0, 'ssdp': 82, 'snmp': 80.0}, 'direct': {'arp': 86.66666666666666, 'tcp': 82.57575757575758, 'fraggle': 80.0}},
              'FS4': {'reflection': {'tcp': 58.33333333333333, 'ssdp': 61, 'snmp': 66.66666666666666}, 'direct': {'arp': 86.66666666666666, 'tcp': 64.58333333333333, 'fraggle': 66.66666666666666}}}


    third = {'FS1': {'reflection': {'tcp': 76.25, 'ssdp': 79, 'snmp': 86.66666666666667}, 'direct': {'arp': 86.66666666666666, 'tcp': 76.78030303030303, 'fraggle': 80.0}},
             'FS2': {'reflection': {'tcp': 68.75, 'ssdp': 67, 'snmp': 66.66666666666666}, 'direct': {'arp': 73.33333333333333, 'tcp': 60.41666666666666, 'fraggle': 66.66666666666666}},
             'FS3': {'reflection': {'tcp': 76.25, 'ssdp': 79, 'snmp': 93.33333333333333}, 'direct': {'arp': 86.66666666666666, 'tcp': 76.66666666666666, 'fraggle': 80.0}},
             'FS4': {'reflection': {'tcp': 68.75, 'ssdp':67, 'snmp': 66.66666666666666}, 'direct': {'arp': 86.66666666666666, 'tcp': 62.49999999999999, 'fraggle': 66.66666666666666}}}

    sets = ["FS1", "FS2", "FS3", "FS4"]
    s = [first, second, third]
    reflective_averages = {fs: [] for fs in sets}
    direct_averages = {fs: [] for fs in sets}
    import numpy as np
    for d in s:
        for fs in d:
            vals = list(d[fs]['reflection'].values())
            reflective_averages[fs].append(np.mean(vals))
            direct_averages[fs].append(np.mean(list(d[fs]['direct'].values())))

    # plot_attack_rate(reflective_averages, "Medium Rate Reflective Attacks")
    plot_attack_rate(direct_averages, "Medium Rate Direct Attacks")


def fs_high_rate():
    first = {'FS1': {'reflection': {'tcp': 87.5, 'ssdp': 95, 'snmp': 100.0}, 'direct': {'arp': 53.33333333333333, 'tcp': 88.75, 'fraggle': 100.0}},
             'FS2': {'reflection': {'tcp': 72.91666666666666, 'ssdp': 75, 'snmp': 77.77777777777777}, 'direct': {'arp': 73.33333333333333, 'tcp': 66.66666666666666, 'fraggle': 66.66666666666666}},
             'FS3': {'reflection': {'tcp': 87.5, 'ssdp': 92, 'snmp': 100.0}, 'direct': {'arp': 93.33333333333333, 'tcp': 90.0, 'fraggle': 100.0}},
             'FS4': {'reflection': {'tcp': 72.91666666666666, 'ssdp': 75, 'snmp': 77.77777777777777}, 'direct': {'arp': 80.0, 'tcp': 75.0, 'fraggle': 66.66666666666666}}}
    second = {'FS1': {'reflection': {'tcp': 81.25, 'ssdp': 84, 'snmp': 86.66666666666667}, 'direct': {'arp': 93.33333333333333, 'tcp': 86.25, 'fraggle': 80.0}},
              'FS2': {'reflection': {'tcp': 60.41666666666666, 'ssdp': 72, 'snmp': 77.77777777777777}, 'direct': {'arp': 73.33333333333333, 'tcp': 66.66666666666666, 'fraggle': 66.66666666666666}},
              'FS3': {'reflection': {'tcp': 80.0, 'ssdp': 84.5, 'snmp': 86.66666666666667}, 'direct': {'arp': 96.66666666666667, 'tcp': 86.25, 'fraggle': 80.0}},
              'FS4': {'reflection': {'tcp': 68.75, 'ssdp': 74.5, 'snmp': 77.77777777777777}, 'direct': {'arp': 80.0, 'tcp': 64.58333333333333, 'fraggle': 66.66666666666666}}}

    third = {'FS1': {'reflection': {'tcp': 73.75, 'ssdp': 80, 'snmp': 86.66666666666667}, 'direct': {'arp': 80.66666666666667, 'tcp': 78.75, 'fraggle': 80.0}},
             'FS2': {'reflection': {'tcp': 75.0, 'ssdp': 76, 'snmp': 77.77777777777777}, 'direct': {'arp': 80.0, 'tcp': 66.66666666666666, 'fraggle': 66.66666666666666}},
             'FS3': {'reflection': {'tcp': 73.75, 'ssdp': 84, 'snmp': 86.66666666666667}, 'direct': {'arp': 96.66666666666667, 'tcp': 78.75, 'fraggle': 80.0}},
             'FS4': {'reflection': {'tcp': 75.0, 'ssdp': 76, 'snmp': 77.77777777777777}, 'direct': {'arp': 80.0, 'tcp': 72.91666666666666, 'fraggle': 66.66666666666666}}}

    sets = ["FS1", "FS2", "FS3", "FS4"]
    s = [first, second, third]
    reflective_averages = {fs: [] for fs in sets}
    direct_averages = {fs: [] for fs in sets}
    import numpy as np
    for d in s:
        for fs in d:
            vals = list(d[fs]['reflection'].values())
            reflective_averages[fs].append(np.mean(vals))
            direct_averages[fs].append(np.mean(list(d[fs]['direct'].values())))


    # print(direct_averages)
    # print(reflective_averages)
    plot_attack_rate(reflective_averages, "High Rate Reflective Attacks")
    plot_attack_rate(direct_averages, "High Rate Direct Attacks")


def table_results():
    import numpy as np
    low_first = {'FS1': {'reflection': {'tcp': 64.54545454545455, 'ssdp': 40.8, 'snmp': 50.0}, 'direct': {'arp': 62.0, 'tcp': 65.05681818181819, 'fraggle': 90.0}},
              'FS2': {'reflection': {'tcp': 58.33333333333333, 'ssdp': 52.5, 'snmp': 44.444444444444436}, 'direct': {'arp': 33.33333333333333, 'tcp': 47.91666666666666, 'fraggle': 33.33333333333333}},
              'FS3': {'reflection': {'tcp': 62.36742424242425, 'ssdp': 54.5, 'snmp': 44.44444444444445}, 'direct': {'arp': 54.666666666666664, 'tcp': 60.227272727272734, 'fraggle': 90.0}},
              'FS4': {'reflection': {'tcp': 60.416666666666664, 'ssdp': 60, 'snmp': 44.444444444444436}, 'direct': {'arp': 39.99999999999999, 'tcp': 49.99999999999999, 'fraggle': 33.33333333333333}}}
    low_second = {'FS1': {'reflection': {'tcp': 65.58712121212122, 'ssdp': 35.7, 'snmp': 44.444444444444436}, 'direct': {'arp': 50.0, 'tcp': 61.51515151515152, 'fraggle': 70.0}},
              'FS2': {'reflection': {'tcp': 58.33333333333333, 'ssdp': 42.3, 'snmp': 44.444444444444436}, 'direct': {'arp': 39.99999999999999, 'tcp': 47.91666666666666, 'fraggle': 33.33333333333333}},
              'FS3': {'reflection': {'tcp': 61.93181818181818, 'ssdp': 45.6, 'snmp': 33.33333333333333}, 'direct': {'arp': 61.333333333333336, 'tcp': 60.96590909090909, 'fraggle': 70.0}},
              'FS4': {'reflection': {'tcp': 58.33333333333333, 'ssdp': 50.3, 'snmp': 33.33333333333333}, 'direct': {'arp': 39.99999999999999, 'tcp': 54.16666666666666, 'fraggle': 33.33333333333333}}}
    low_third = {'FS1': {'reflection': {'tcp': 64.01515151515152, 'ssdp': 30.5, 'snmp': 38.888888888888886}, 'direct': {'arp': 66.0, 'tcp': 62.026515151515156, 'fraggle': 70.0}},
             'FS2': {'reflection': {'tcp': 56.25, 'ssdp': 40.9, 'snmp': 33.33333333333333}, 'direct': {'arp': 53.33333333333333, 'tcp': 41.66666666666666, 'fraggle': 49.99999999999999}},
             'FS3': {'reflection': {'tcp': 64.01515151515152, 'ssdp': 45.6, 'snmp': 27.77777777777777}, 'direct': {'arp': 50.0, 'tcp': 54.659090909090914, 'fraggle': 90.0}},
             'FS4': {'reflection': {'tcp': 56.25, 'ssdp': 60.4, 'snmp': 33.33333333333333}, 'direct': {'arp': 60.0, 'tcp': 54.16666666666666, 'fraggle': 49.99999999999999}}}
    med_first = {'FS1': {'reflection': {'tcp': 82.5, 'ssdp': 90, 'snmp': 93.33333333333333}, 'direct': {'arp': 82.0, 'tcp': 72.4621212121212, 'fraggle': 90.0}},
             'FS2': {'reflection': {'tcp': 54.166666666666664, 'ssdp': 65, 'snmp': 66.66666666666666}, 'direct': {'arp': 60.0, 'tcp': 60.416666666666664, 'fraggle': 66.66666666666666}},
             'FS3': {'reflection': {'tcp': 92.5, 'ssdp': 75.6, 'snmp': 86.66666666666667}, 'direct': {'arp': 79.33333333333333, 'tcp': 86.09848484848484, 'fraggle': 90.0}},
             'FS4': {'reflection': {'tcp': 64.58333333333333, 'ssdp': 55, 'snmp': 44.444444444444436}, 'direct': {'arp': 60.0, 'tcp': 70.83333333333333, 'fraggle': 66.66666666666666}}}
    med_second = {'FS1': {'reflection': {'tcp': 83.75, 'ssdp': 81, 'snmp': 86.66666666666667}, 'direct': {'arp': 86.0, 'tcp': 80.30303030303031, 'fraggle': 70.0}},
              'FS2': {'reflection': {'tcp': 58.33333333333333, 'ssdp': 53, 'snmp': 55.55555555555554}, 'direct': {'arp': 66.66666666666666, 'tcp': 64.58333333333333, 'fraggle': 66.66666666666666}},
              'FS3': {'reflection': {'tcp': 85.0, 'ssdp': 82, 'snmp': 80.0}, 'direct': {'arp': 86.66666666666666, 'tcp': 82.57575757575758, 'fraggle': 80.0}},
              'FS4': {'reflection': {'tcp': 58.33333333333333, 'ssdp': 61, 'snmp': 66.66666666666666}, 'direct': {'arp': 86.66666666666666, 'tcp': 64.58333333333333, 'fraggle': 66.66666666666666}}}
    med_third = {'FS1': {'reflection': {'tcp': 76.25, 'ssdp': 79, 'snmp': 86.66666666666667}, 'direct': {'arp': 86.66666666666666, 'tcp': 76.78030303030303, 'fraggle': 80.0}},
             'FS2': {'reflection': {'tcp': 68.75, 'ssdp': 67, 'snmp': 66.66666666666666}, 'direct': {'arp': 73.33333333333333, 'tcp': 60.41666666666666, 'fraggle': 66.66666666666666}},
             'FS3': {'reflection': {'tcp': 76.25, 'ssdp': 79, 'snmp': 93.33333333333333}, 'direct': {'arp': 86.66666666666666, 'tcp': 76.66666666666666, 'fraggle': 80.0}},
             'FS4': {'reflection': {'tcp': 68.75, 'ssdp':67, 'snmp': 66.66666666666666}, 'direct': {'arp': 86.66666666666666, 'tcp': 62.49999999999999, 'fraggle': 66.66666666666666}}}
    high_first = {'FS1': {'reflection': {'tcp': 87.5, 'ssdp': 95, 'snmp': 100.0}, 'direct': {'arp': 53.33333333333333, 'tcp': 88.75, 'fraggle': 100.0}},
             'FS2': {'reflection': {'tcp': 72.91666666666666, 'ssdp': 75, 'snmp': 77.77777777777777}, 'direct': {'arp': 73.33333333333333, 'tcp': 66.66666666666666, 'fraggle': 66.66666666666666}},
             'FS3': {'reflection': {'tcp': 87.5, 'ssdp': 92, 'snmp': 100.0}, 'direct': {'arp': 93.33333333333333, 'tcp': 90.0, 'fraggle': 100.0}},
             'FS4': {'reflection': {'tcp': 72.91666666666666, 'ssdp': 75, 'snmp': 77.77777777777777}, 'direct': {'arp': 80.0, 'tcp': 75.0, 'fraggle': 66.66666666666666}}}
    high_second = {'FS1': {'reflection': {'tcp': 81.25, 'ssdp': 84, 'snmp': 86.66666666666667}, 'direct': {'arp': 93.33333333333333, 'tcp': 86.25, 'fraggle': 80.0}},
              'FS2': {'reflection': {'tcp': 60.41666666666666, 'ssdp': 72, 'snmp': 77.77777777777777}, 'direct': {'arp': 73.33333333333333, 'tcp': 66.66666666666666, 'fraggle': 66.66666666666666}},
              'FS3': {'reflection': {'tcp': 80.0, 'ssdp': 84.5, 'snmp': 86.66666666666667}, 'direct': {'arp': 96.66666666666667, 'tcp': 86.25, 'fraggle': 80.0}},
              'FS4': {'reflection': {'tcp': 68.75, 'ssdp': 74.5, 'snmp': 77.77777777777777}, 'direct': {'arp': 80.0, 'tcp': 64.58333333333333, 'fraggle': 66.66666666666666}}}
    high_third = {'FS1': {'reflection': {'tcp': 73.75, 'ssdp': 80, 'snmp': 86.66666666666667}, 'direct': {'arp': 80.66666666666667, 'tcp': 78.75, 'fraggle': 80.0}},
             'FS2': {'reflection': {'tcp': 75.0, 'ssdp': 76, 'snmp': 77.77777777777777}, 'direct': {'arp': 80.0, 'tcp': 66.66666666666666, 'fraggle': 66.66666666666666}},
             'FS3': {'reflection': {'tcp': 73.75, 'ssdp': 84, 'snmp': 86.66666666666667}, 'direct': {'arp': 96.66666666666667, 'tcp': 78.75, 'fraggle': 80.0}},
             'FS4': {'reflection': {'tcp': 75.0, 'ssdp': 76, 'snmp': 77.77777777777777}, 'direct': {'arp': 80.0, 'tcp': 72.91666666666666, 'fraggle': 66.66666666666666}}}

    lists = [low_first, low_second, low_third, med_first, med_second, med_third, high_first, high_second, high_third]
    sets = ["FS1", "FS2", "FS3", "FS4"]
    averages = {
        'FS1':{
            'reflection':{
                'tcp': [],
                'ssdp':[],
                'snmp':[]
            },
            'direct':{
                'arp': [],
                'tcp':[],
                'fraggle':[]
            }
        },
        'FS2': {
            'reflection': {
                'tcp': [],
                'ssdp': [],
                'snmp': []
            },
            'direct': {
                'arp': [],
                'tcp': [],
                'fraggle': []
            }
        },
        'FS3': {
            'reflection': {
                'tcp': [],
                'ssdp': [],
                'snmp': []
            },
            'direct': {
                'arp': [],
                'tcp': [],
                'fraggle': []
            }
        },
        'FS4': {
            'reflection': {
                'tcp': [],
                'ssdp': [],
                'snmp': []
            },
            'direct': {
                'arp': [],
                'tcp': [],
                'fraggle': []
            }
        }
    }
    for d in lists:
        for fs in d:
            for attack_type in d[fs]:
                for attack in d[fs][attack_type]:
                    averages[fs][attack_type][attack].append(d[fs][attack_type][attack])

    # print(averages)
    for f in averages:
        for attack_t in averages[f]:
            for a in averages[f][attack_t]:
                print(f, attack_t, a, np.mean(averages[f][attack_t][a]))
                print('-------------')



def find_ordinal(device, file):
    print("finding ordianal")
    ordinal_check = [3043317, 3134056, 3259364, 4292026]
    saved_traffic = Path(r"C:\Users\amith\Documents\Uni\Masters\JNCA\traffic\processed-traffic\Attack")
    traffic = unpickle_network_trace_and_device_obj(str(saved_traffic), files='_18-06-01', devices=device)
    found_ordinal = []
    for network_obj in traffic:
        for device_obj in traffic[network_obj]:
            flow_table = device_obj.merge_flow_dict()
            for flow in flow_table:
                for pkt in flow_table[flow]:
                    if pkt['ordinal'] in ordinal_check:
                        print('found ordinal')
                        direction = None
                        if flow in device_obj.flows['incoming']:
                            direction = 'inputs'
                        else:
                            direction = 'output'
                        found_ordinal.append((pkt, flow, direction))

    for data in found_ordinal:
        print(data)


first = [(20088.0, 20688.0), (16870.0, 17470.0), (18477.0, 19077.0), (42538.0, 43139.0), (44149.0, 44750.0), (45760.0, 46360.0),
         (71464.0, 72064.0), (73079.0, 73679.0), (61400.0, 62000.0), (58199.0, 58800.0), (59800.0, 60400.0)]

second = [(30911.0, 31512.0), (32524.0, 33124.0), (34131.0, 34732.0), (304.0, 904.0), (59279.0, 59879.0), (60892.0, 61492.0),
          (62518.0, 63118.0), (25114.0, 25715.0), (26715.0, 27315.0), (28315.0, 28915.0)]










