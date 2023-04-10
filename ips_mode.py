# -*-coding:utf-8-*-

import os
import time
import json
import netfilterqueue
from scapy.all import *

def deny_write_log(log: str):
    fp = open("active_response.log", "a+")
    fp.write(log)
    fp.close()

def deny_ip_in (logdata: str, ip: str, timeout: str):
    timeout = int(timeout)
    rule_check_in = f'iptables-save | grep -- "INPUT -s {ip}/32 -j DROP"'
    # 下面的日志中，时间是规则被触发的时间，而不是iptables被调用的时间
    if os.popen(rule_check_in).read() == "":
        if os.system(f"iptables -I INPUT -s {ip} -j DROP") == 0:
            log = f"{logdata}----源ip:[{ip}]被禁止入站{timeout}秒\n"
            # print(log)
            deny_write_log(log)
            time.sleep(timeout)
            if os.system(f"iptables -D INPUT -s {ip} -j DROP") == 0:
                log = f"{logdata}----源ip:[{ip}]解除入站限制\n"
                # print(log)
                deny_write_log(log)

def deny_ip_out (logdata: str, ip: str, timeout: str):
    timeout = int(timeout)
    rule_check_out = f'iptables-save | grep -- "OUTPUT -d {ip}/32 -j DROP"'
    if os.popen(rule_check_out).read() == "":
        if os.system(f"iptables -I OUTPUT -d {ip} -j DROP") == 0:
            log = f"{logdata}----目的ip:[{ip}]被禁止出站{timeout}秒\n"
            # print(log)
            deny_write_log(log)
            time.sleep(timeout)
            if os.system(f"iptables -D OUTPUT -d {ip} -j DROP") == 0:
                log = f"{logdata}----目的ip:[{ip}]解除出站限制\n"
                # print(log)
                deny_write_log(log)

def open_nfq(config:dict):
    tcp_dict = config['protocol_port']['tcp']
    udp_dict = config['protocol_port']['udp']
    for protocol,ports in tcp_dict.items():
        for port in ports.split(";"):
            # 排除ssh，方便测试
            if protocol != "ssh":
                os.system(f"iptables -I INPUT -p tcp --dport {port} -j NFQUEUE --queue-num 1")
                os.system(f"iptables -I OUTPUT -p tcp --sport {port} -j NFQUEUE --queue-num 1")
    for protocol,ports in udp_dict.items():
        for port in ports.split(";"):
            os.system(f"iptables -I INPUT -p udp --dport {port} -j NFQUEUE --queue-num 1")
            os.system(f"iptables -I OUTPUT -p udp --sport {port} -j NFQUEUE --queue-num 1")
    os.system(f"iptables -I INPUT -p icmp -j NFQUEUE --queue-num 1")
    os.system(f"iptables -I OUTPUT -p icmp -j NFQUEUE --queue-num 1")

def drop_wirte_log(log: str):
    if log != []:
        fp = open("nfq.log", "a+")
        fp.write(f"{log}--触发nfq,已drop\n")
        fp.close()


if __name__ == "__main__":
    config = json.load(open("config.json"))
    open_nfq(config)