from scapy.all import *
import logging
import argparse
import netifaces

logging.basicConfig(level=logging.INFO)
from datetime import datetime

my_traffic=[]
senders=set()
sender_count={}

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
    if args.iface is not None:
        log_with_file("INFO", "Using " + args.iface)
        return args.iface
    else:
        for i in range(len(netifaces.interfaces())):
            print(i + 1, "-", netifaces.interfaces()[i])
        iface = input("Select the Interface|>")
        return netifaces.interfaces()[int(iface) - 1]

def detect_attacks():
    sender_count={}

    for IP in senders:
        if()
        sender_count[IP] = sender_count[IP]+1

    for IP in sender_count:
        print(1)




def funct(x):
    my_traffic.append(x)
    print(x.summary())
    senders.add(x["IP"].src)
    detect_attacks()


def sniff_fun(iface):
    sniffer = AsyncSniffer(iface=iface,prn=funct)
    sniffer.start()

    input("Start IDS Agent - Press any key to STOP |> ")
    sniffer.stop()
    #sniffed = sniffer.results
    print(my_traffic[0].summary())


def main():
    iface = init()
    sniff_fun(iface)


main()
