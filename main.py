#! /usr/bin/python3

from scapy.all import *
import logging
import argparse
import netifaces
from datetime import datetime
import time
from os import system, name

logging.basicConfig(level=logging.NOTSET)


my_traffic = []
scan_count = {}
syn_flood_count = {}
scan_threshold = 100
my_ip = ""
threshold_time = 10
threshold_ports = 20

syn_threshold = 100
syn_threshold_time = 2
verbose = False


def clear():
    # for windows
    if name == 'nt':
        _ = system('cls')
    else:
        _ = system('clear')


def log_with_file(type, log):  # print log and write to the file
    log_str = str(datetime.now().strftime("%d-%b-%Y (%H:%M:%S-%f)")) + " - " + type + " - " + log

    if type == "LOG_TRAFFIC_SUMMARY":
        with open("Traffic_Summary.log", "a") as my_file:
            my_file.write(log_str + "\n")
    else:
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
    parser.add_argument('-v', action="store_true", help='Verbose')

    args = parser.parse_args()
    global my_ip
    if args.v:  # set the verbosity
        global verbose
        verbose = True
    if args.iface is not None:  # set the interface from the CMD
        log_with_file("INFO", "Using " + args.iface)
        try:
            netifaces.ifaddresses(args.iface)
        except:
            print("Wrong Interface")
            quit()
        my_ip = netifaces.ifaddresses(args.iface)[netifaces.AF_INET][0]['addr']
        print("My IP: " + my_ip)
        return args.iface
    else:  # set the interface from a list of interfaces
        for i in range(len(netifaces.interfaces())):
            print(i + 1, "-", netifaces.interfaces()[i])
        iface = input("Select the Interface|>")
        try:
            netifaces.ifaddresses(netifaces.interfaces()[int(iface) - 1])
        except:
            print("Wrong Interface")
            quit()

        my_ip = netifaces.ifaddresses(netifaces.interfaces()[int(iface) - 1])[netifaces.AF_INET][0]['addr']
        print("My IP: " + my_ip)
        return netifaces.interfaces()[int(iface) - 1]


def count_connections(connections, threshold_time):  # count the connections in a  range of time
    total = 0
    now = time.time()
    for t in connections["timestamp"]:
        if now - t < threshold_time:
            total = total + 1
    return total


def count_ports(port_list, threshold):  # count the ports in a certan time "Threshold is the array of the connection
    # in a range of time"
    ports = port_list[1 - threshold:-1]
    return len(set(ports))


def count_ports_syn(port_list, threshold):  # return the port with the max number of connection in a "threshold" time
    ports = port_list[1 - threshold:-1]
    ports_count = {}
    for i in list(set(ports)):
        ports_count[str(i)] = 0

    for i in ports:
        ports_count[str(i)] = ports_count[str(i)] + 1

    return max(ports_count.values())


def detect_attacks():
    attacks_to_print = []

    for IP in scan_count:  # scan detection
        if count_connections(scan_count[IP], threshold_time) > scan_threshold and count_ports(scan_count[IP]["ports"],
                                                                                 count_connections(
                                                                                     scan_count[IP],
                                                                                     threshold_time)) > threshold_ports:
            attacks_to_print.append(" " + str(IP) + " Scan you!")

    for IP in syn_flood_count:  # syn flood detection
        if count_connections(syn_flood_count[IP], syn_threshold_time) > syn_threshold and count_ports_syn(
                syn_flood_count[IP]["ports"],
                count_connections(scan_count[IP], syn_threshold_time)) > syn_threshold:
            attacks_to_print.append(" " + str(IP) + " Syn Flood")
    if not verbose:
        clear()
    for attacks in attacks_to_print:  # output
        log_with_file("ALERT", attacks)


def single_connection(x):
    my_traffic.append(x)
    log_with_file("LOG_TRAFFIC_SUMMARY", x.summary())
    if verbose:
        print(x.summary())
    global my_ip
    try:
        if x["IP"].src != my_ip:

            if x["IP"].src in scan_count.keys():  # Update info of Scan Detection
                scan_count[x["IP"].src]["n"] = scan_count[x["IP"].src]["n"] + 1
                scan_count[x["IP"].src]["timestamp"].append(time.time())

                if x["TCP"].dport is not None:
                    scan_count[x["IP"].src]["ports"].append(x["TCP"].dport)
                else:
                    scan_count[x["IP"].src]["ports"].append(x["UDP"].dport)

            else:
                if x["TCP"].dport is not None:
                    scan_count[x["IP"].src] = {"n": 1, "ports": [x["TCP"].dport], "start-time": time.time(),
                                               "IP": x["IP"].src, "timestamp": [time.time()]}

        if x["IP"].src in syn_flood_count.keys():  # Update info of Syn Flood Detection
            if x["TCP"].dport is not None:
                if x["TCP"].flags == 2:
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
        # print(e)
        pass

    now = time.time()
    if int((now - int(now)) * 100) == 0:
        detect_attacks()


def sniff_fun(iface):
    sniffer = AsyncSniffer(iface=iface, prn=single_connection)  # Async Sniffing
    sniffer.start()

    input("Start IDS Agent - Press any key to STOP |> ")
    sniffer.stop()
    # sniffed = sniffer.results


def main():
    iface = init()
    sniff_fun(iface)


if __name__ == "__main__":
    main()
