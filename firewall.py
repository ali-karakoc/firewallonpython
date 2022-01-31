"""
DONE: Block connections based on port
TODO: Check incoming ips rep
DONE: Syn flood attack protection
DONE: Dos protection
DONE: Log every suspicious packet to a pcap file
"""

import pydivert
from util.pydivertwriter import PydivertWriter
import threading
from time import sleep
import ipaddress
import requests

port_list = list()      # Ports that firewall will block incoming connections
icmp_packets = dict()   # ip:count refreshes every REFRESH_RATE min
syn_packets = dict()    # ip:count refreshes every REFRESH_RATE min
REFRESH_RATE = 10
ICMP_PACKET_COUNT = 15  # max {icmp} packet allowed from a certain ip
SYN_PACKET_COUNT = 30   # max {syn}  packet allowed from a certain ip
log_file = PydivertWriter("firewall_log.pcap", sync=True, append=True)


def icmp_logic(w, packet):
    packet_ip = packet.src_addr
    print(f"DEBUG -> GOT A PING PACKET FROM {packet_ip}")
    # Adding packet to dict and adding to it
    if packet_ip in icmp_packets:
        icmp_packets[packet_ip] += 1
    else:
        icmp_packets[packet_ip] = 0
        icmp_packets[packet_ip] += 1
    # if max count has been reached disallow packet
    if icmp_packets[packet_ip] > ICMP_PACKET_COUNT:
        print(f"Too many ping requests from: {packet_ip} dropping packets")
        # This is here to prevent the pcap file getting too big
        if icmp_packets[packet_ip]-ICMP_PACKET_COUNT < 10:
            log_file.write(packet)
    else:
        w.send(packet)


def syn_logic(w, packet):
    packet_ip = packet.src_addr
    print(f"DEBUG -> GOT A SYN PACKET FROM {packet_ip}")
    # adding one to dict value if exist else create one then add
    if packet_ip in syn_packets:
        syn_packets[packet_ip] += 1
    else:
        syn_packets[packet_ip] = 0
        syn_packets[packet_ip] += 1
    print(f"{syn_packets}")
    # if max count has been reached disallow packet
    if syn_packets[packet_ip] > SYN_PACKET_COUNT:
        print(f"Too many syn requests from: {packet_ip} dropping packets")
        # This is here to prevent the pcap file getting too big
        if syn_packets[packet_ip] - SYN_PACKET_COUNT < 10:
            log_file.write(packet)
    else:
        w.send(packet)


def blacklist_check(ip):
    pass


# this is not the best way
def clear_loop():
    global icmp_packets
    global syn_packets
    global REFRESH_RATE

    while True:
        sleep(REFRESH_RATE * 60)
        icmp_packets = dict()
        syn_packets = dict()

origin = "global" # çagrı kaynagının menşei / ülkesi

# ipinfo.io adresinden ip numarasına göre ip özelliklerini döndürmektedir
def get_ipinfo(ip):  
    endpoint = f'https://ipinfo.io/{ip}/json'
    # "Authorization: Bearer $TOKEN" 
    # headers = "Accept: application/json"
    headers={"Authorization": "Bearer "}
    global origin
    try:
        response = requests.get(endpoint, verify=True)
        if response.status_code != 200:
            return 'Status:', response.status_code, 'Problem with the request. Exiting.'
       
        data=response.json()

        if origin == "" and 'country' in data.keys():
            origin = data["country"]
        # return data["country"]
    except (ConnectionError, TimeoutError):
        print("Will retry again in a little bit")
    except Exception as e:
        print(f"Exception : {e}")

threading.Thread(target=clear_loop).start()
threads = []
with pydivert.WinDivert("tcp.Syn or icmp") as w:
    for packet in w:
        # print(f"{packet.src_addr}-{packet.dst_addr}")
        # if karar yapısı gelen çağrının hangi ülkeden geldipini sorgulamaktadır
        # Bunun icin get_ipinfo fonksiyonunu kullanmaktadır
        if  ipaddress.ip_address(packet.src_addr).is_private != True:
            origin = ""
            t = threading.Thread(target=get_ipinfo, args=(packet.src_addr,))
            threads.append(t)
            t.start()
     
        # skips if blacklisted port
        if packet.dst_port in port_list:
            continue
        elif packet.icmp:
            icmp_logic(w, packet)
        elif packet.tcp.syn:
            ''' Bu satırlar cağrının kaynagı TR ise işleme almaktadır
                    print(f"originım : {origin}")
                    if origin == "TR":
                Not origine göre çalışmak için if yapısından yorumu kaldırmak gerekiyor
            '''
            print(f"originim : {origin}")

            if origin == "TR": 
                syn_logic(w, packet)
        else:
            w.send(packet)
