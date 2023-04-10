# -*-coding:utf-8-*-
import os
import time
import netfilterqueue
from scapy.all import *
from scapy.all import raw,bytes_hex
import json
import sys
import getopt

# 自定义模块
import rules_op
import inter_mode
import check_op

def do_capture(flow,nfq):
    print(1)
    scapy_flow = IP(flow.get_payload())
    try:
        print(scapy_flow['Raw'].load.decode())
    except:
        # print(scapy_flow.show())
        pass
    flow.accept()

def http_handler(pkt):
    # 将 netfilterqueue 截获的报文转换成scapy形式的数据包，利于后续进行分析和修改
    scapy_packet = IP(pkt.get_payload())
    print(scapy_packet)
    package = ''
    try:
        # 取出数据包的最上层数据，并解码，去除开头结尾的空格 
        package = scapy_packet.lastlayer().original.decode().strip()
    except:
        pass
    # 此处判断取出的数据是否以‘GET’开头，确定其HTTP的GET请求并进一步    
    if package.startswith('GET'):
        # 将 GET 请求头部所有字段按行取出
        req_lines = package.split('\r\n')
        # 取出GET请求的请求路径，并使用攻击检测函数进行检测
        attacktype = attack_check(req_lines[0])
        # 判断是否有攻击行为，有则输出攻击信息，并将数据包丢掉
        if attacktype :
            # 输出攻击消息，此处可以自己编写输出到日志文件或数据库中
            print(f'attacktype:{attacktype} IPsrc:[{scapy_packet.src}] time:{datetime.now().strftime("%Y-%m-%d %H:%M:%S")} action: drop')
            # 丢掉数据包
            pkt.drop(); 
        else:
            # 接收数据包
            pkt.accept()
    else:
        # 接收数据包
        pkt.accept(); 

        
def attack_check(payload):
    # 此处只是验证，自己可完善检测函数，编写对应检测规则的文件
    if 'and%201=1' in payload :
        print('检测到SQL注入攻击')
        return 'SQL_injection'
    else:
        return False




if __name__ == '__main__':
    # 创建netfilterqueue实例对象
    filter = netfilterqueue.NetfilterQueue()
    # 将监听队列0与http_handler绑定，将拦截的包传入该函数中
    filter.bind(1, do_capture)
    # 运行netfilterqueue，进行数据包拦截
    filter.run()