from scapy.all import *
import logging
import argparse
import netifaces

logging.basicConfig(level=logging.INFO)
from datetime import datetime
import time

my_traffic = []
senders = set()
sender_count = {}
threshold = 100
my_ip = ""
threshold_time = 10
threshold_ports = 20


def log_with_file(type, log):
    log_str = "\t\t" + str(datetime.now().strftime("%d-%b-%Y (%H:%M:%S-%f)")) + " - " + type + " - " + log
    with open("IDS.log", "a") as my_file:
        my_file.write(log_str + "\n")
    if type == "INFO":
        logging.info(log_str)


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


def detect_attacks(sender_count):
    # "n": 1, "ports": [x["TCP"].dport], "start-time": time.time()}
    for IP in sender_count:
        #print(IP + "\t-\t" + str(sender_count[IP]))
        if sender_count[IP]["n"] > threshold and time.time() - sender_count[IP]["start-time"] < threshold_time and len(
                sender_count[IP]["ports"]) > threshold_ports:
            log_with_file("ALERT", str(IP) + "scan you!")
            print(str(IP) + "\tscan you!")


def funct(x):
    my_traffic.append(x)
    # print(x.summary())
    global my_ip
    try:
        if x["IP"].src != my_ip:

            if x["IP"].src in sender_count.keys():
                sender_count[x["IP"].src]["n"] = sender_count[x["IP"].src]["n"] + 1
                if x["TCP"].dport is not None:
                    sender_count[x["IP"].src]["ports"] = list(
                        set(sender_count[x["IP"].src]["ports"] + [x["TCP"].dport]))
                else:
                    sender_count[x["IP"].src]["ports"] = list(
                        set(sender_count[x["IP"].src]["ports"] + [x["UDP"].dport]))

            else:
                sender_count[x["IP"].src] = {"n": 1, "ports": [x["TCP"].dport], "start-time": time.time(),"IP":x["IP"].src}
    except:
        pass
    detect_attacks(sender_count)


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
