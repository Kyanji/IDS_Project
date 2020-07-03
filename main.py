from scapy.all import *
import logging
import argparse
import netifaces
import numpy as np

logging.basicConfig(level=logging.INFO)
from datetime import datetime
import time

my_traffic = []
senders = set()
sender_count = {}
syn_flood_count = {}
threshold = 100
my_ip = ""
threshold_time = 10
threshold_ports = 20

syn_threshold = 100
syn_threshold_time = 2

last_attack = [np.inf, np.inf]
clean_seconds = 4


def log_with_file(type, log):
    log_str = "\t\t" + str(datetime.now().strftime("%d-%b-%Y (%H:%M:%S-%f)")) + " - " + type + " - " + log
    with open("IDS.log", "a") as my_file:
        my_file.write(log_str + "\n")
    if type == "INFO":
        logging.info(log_str)
    if type == "ALERT":
        logging.warning(log_str)


def init():
    parser = argparse.ArgumentParser(description='IDS')
    parser.add_argument('--iface', type=str,
                        help='Interface')
    args = parser.parse_args()
    global my_ip
    if args.iface is not None:
        log_with_file("INFO", "Using " + args.iface)
        netifaces.ifaddresses(args.iface)
        my_ip = netifaces.ifaddresses(args.iface)[netifaces.AF_INET][0]['addr']
        print(my_ip)  # should print "192.168.100.37"
        return args.iface
    else:
        for i in range(len(netifaces.interfaces())):
            print(i + 1, "-", netifaces.interfaces()[i])
        iface = input("Select the Interface|>")
        netifaces.ifaddresses(netifaces.interfaces()[int(iface) - 1])
        my_ip = netifaces.ifaddresses(netifaces.interfaces()[int(iface) - 1])[netifaces.AF_INET][0]['addr']
        print(my_ip)  # should print "192.168.100.37"
        return netifaces.interfaces()[int(iface) - 1]


def count_connections(connections, threshold_time):
    total = 0
    now = time.time()
    for t in connections["timestamp"]:
        if now - t < threshold_time:
            total = total + 1
    return total


def count_ports(port_list, threshold):
    ports = port_list[1 - threshold:-1]
    return len(set(ports))


def count_ports_syn(port_list, threshold):
    ports = port_list[1 - threshold:-1]
    ports_count = {}
    for i in list(set(ports)):
        ports_count[str(i)] = 0

    for i in ports:
        ports_count[str(i)] = ports_count[str(i)] + 1

    return max(ports_count.values())


def detect_attacks():
    # scan detection
    IP_to_delete_scan = []
    for IP in sender_count:
        # print(IP + "\t-\t" + str(sender_count[IP]))
        if count_connections(sender_count[IP], threshold_time) > threshold and count_ports(sender_count[IP]["ports"],
                                                                                           count_connections(
                                                                                                   sender_count[IP],
                                                                                                   threshold_time)) > threshold_ports:
            # if sender_count[IP]["n"] > threshold and time.time() - sender_count[IP]["start-time"] < threshold_time and len(
            #         sender_count[IP]["ports"]) > threshold_ports:
            log_with_file("ALERT", " " + str(IP) + "scan you!")
            print(str(IP) + "\tscan you!")
    # if IP_to_delete_scan != []:
    #     for IP in IP_to_delete_scan:
    #         del sender_count[IP]
    #         print("del")
    #     IP_to_delete_scan = []

    for IP in syn_flood_count:

        if count_connections(syn_flood_count[IP], syn_threshold_time) > syn_threshold and count_ports_syn(
                syn_flood_count[IP]["ports"],
                count_connections(sender_count[IP], syn_threshold_time)) > syn_threshold:
            log_with_file("ALERT", " " + str(IP) + "Syn Flood")
            print(str(IP) + "\tSyn Flood")
            last_attack[1] = time.time()


def funct(x):
    my_traffic.append(x)
    # print(x.summary())
    global my_ip
    try:
        if x["IP"].src != my_ip:

            if x["IP"].src in sender_count.keys():
                sender_count[x["IP"].src]["n"] = sender_count[x["IP"].src]["n"] + 1
                sender_count[x["IP"].src]["timestamp"].append(time.time())

                if x["TCP"].dport is not None:
                    sender_count[x["IP"].src]["ports"].append(x["TCP"].dport)
                else:
                    sender_count[x["IP"].src]["ports"].append(x["UDP"].dport)

            else:
                if x["TCP"].dport is not None:
                    sender_count[x["IP"].src] = {"n": 1, "ports": [x["TCP"].dport], "start-time": time.time(),
                                                 "IP": x["IP"].src, "timestamp": [time.time()]}

        if x["IP"].src in syn_flood_count.keys():
            if x["TCP"].dport is not None:
                if x["TCP"].flags == 2:  # Syn Flood Detection
                    syn_flood_count[x["IP"].src]["Syn"] = syn_flood_count[x["IP"].src]["Syn"] + 1
                    syn_flood_count[x["IP"].src]["timestamp"].append(time.time())
                    syn_flood_count[x["IP"].src]["ports"].append(x["TCP"].dport)

        else:
            if x["TCP"].dport is not None:
                if x["TCP"].flags == 2:
                    syn_flood_count[x["IP"].src] = {}
                    syn_flood_count[x["IP"].src]["Syn"] = 1
                    syn_flood_count[x["IP"].src]["ports"] = [x["TCP"].dport]
                    syn_flood_count[x["IP"].src]["Syn_start_time"] = time.time()
                    syn_flood_count[x["IP"].src]["timestamp"] = [time.time()]

    except Exception as e:
        print(e)

    detect_attacks()


def sniff_fun(iface):
    sniffer = AsyncSniffer(iface=iface, prn=funct)
    sniffer.start()

    input("Start IDS Agent - Press any key to STOP |> ")
    sniffer.stop()
    # sniffed = sniffer.results
    print(my_traffic[0].summary())


def main():
    iface = init()
    sniff_fun(iface)


main()
