# -*-coding:utf-8-*-

from scapy.all import *
from scapy.all import raw,bytes_hex
import json
import sys
import getopt
import os
import netfilterqueue

# 自定义模块
import rules_op
import inter_mode
import check_op
import ips_mode

    
def do_capture(flow):
    # print(flow.show())
    ip_layer = flow.getlayer('IP')
    icmp_layer = flow.getlayer('ICMP')
    tcp_layer = flow.getlayer('TCP')
    udp_layer = flow.getlayer('UDP')
    logtime=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    info_data={}
    info_data['logtime']=logtime
    if ip_layer:
        ip_src = ip_layer.src        #提取流量源IP
        ip_dst = ip_layer.dst        #提取流量目的IP
        info_data['ip_src']=ip_src
        info_data['ip_dst']=ip_dst
    if icmp_layer:
        # 目前仅支持ping请求检测
        icmp_type=icmp_layer.type
        if icmp_type == 8:
            payload=flow['ICMP'].load
            try:
                payload=payload.decode()   
            except:
                # 解码报错问题--二进制乱码
                payload=str(payload)
            rules_op.check(icmp_rules,payload,info_data,allow_ip_list,acr)
    if tcp_layer:
        port_src = tcp_layer.sport      #提取流量源port
        port_dst = tcp_layer.dport      #提取流量目的port
        info_data['port_src']=port_src
        info_data['port_dst']=port_dst
        
        #检查tcp协议
        rules_op.check(tcp_rules,str(tcp_layer.flags),info_data,allow_ip_list,acr)

        if 'Raw' in flow:  
            payload = flow['Raw'].load
            try:
                payload=payload.decode()   
            except:
                # 解码报错问题--二进制乱码
                payload=str(payload)

            # 检查tcp的payload
            # rules_op.check(tcp_rules,payload,info_data,allow_ip_list,acr)

            #检查所有tcp上层协议规则
            tcps = protocols['tcp']
            for protocol in tcps.keys():
                if protocol == 'http':
                    # http协议[配置文件端口]
                    ports= tcps[protocol].split(";")
                    if str(port_dst) in ports:
                        # http请求检测
                        rules_op.check(http_req_rules,payload,info_data,allow_ip_list,acr)
                    elif str(port_src) in ports:
                        # http响应检测
                        rules_op.check(http_resp_rules,payload,info_data,allow_ip_list,acr)
                elif protocol == 'mysql':
                    # mysql协议[配置文件端口]
                    ports= tcps[protocol].split(";")
                    if str(port_src) in ports:
                        # mysql响应检测
                        rules_op.check(mysql_resp_rules,payload,info_data,allow_ip_list,acr)
                    elif str(port_dst) in ports:
                        # mysql请求检测
                        rules_op.check(mysql_req_rules,payload,info_data,allow_ip_list,acr)
                elif protocol == 'ssh':
                    # ssh协议[配置文件端口]
                    ports= tcps[protocol].split(";")
                    if str(port_dst) in ports:
                        # ssh请求检测--原始流量
                        # print(bytes_hex(flow))
                        rules_op.check(ssh_rules,str(bytes_hex(flow)),info_data,allow_ip_list,acr)
                elif protocol == 'redis':
                    ports= tcps[protocol].split(";")
                    if str(port_dst) in ports:
                        # redis请求检测
                        rules_op.check(redis_rules,payload,info_data,allow_ip_list,acr)
    elif udp_layer:
        port_src = udp_layer.sport      #提取流量源port
        port_dst = udp_layer.dport      #提取流量目的port
        info_data['port_src']=port_src
        info_data['port_dst']=port_dst
        #检查所有udp上层协议规则
        udps = protocols['udp']
        for protocol in udps.keys():
            if protocol == 'dns':
                # dns协议[配置文件端口]
                ports= udps[protocol].split(";")
                if str(port_dst) in ports:
                    #DNS请求类型
                    #[1, 28, 12]:  A AAAA PTR   [16, 15, 5, 10]: TXT MX CNAME NULL
                    query_type=str(flow['DNS'].qd.qtype)
                    rules_op.check(dns_rules,query_type,info_data,allow_ip_list,acr)
                    #DNS请求域名
                    query_domain=flow['DNS'].qd.qname.decode()
                    rules_op.check(dns_rules,query_domain,info_data,allow_ip_list,acr)

def do_capture_ntf(pkt):
    flow = IP(pkt.get_payload())
    ip_layer = flow.getlayer('IP')
    icmp_layer = flow.getlayer('ICMP')
    tcp_layer = flow.getlayer('TCP')
    udp_layer = flow.getlayer('UDP')
    logtime=time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    info_data={}
    info_data['logtime']=logtime
    drop_flag = 0
    if ip_layer:
        ip_src = ip_layer.src        #提取流量源IP
        ip_dst = ip_layer.dst        #提取流量目的IP
        info_data['ip_src']=ip_src
        info_data['ip_dst']=ip_dst
    if icmp_layer:
          # 目前仅支持ping请求检测
        icmp_type=icmp_layer.type
        if icmp_type == 8:
            payload=flow['ICMP'].load
            try:
                payload=payload.decode()   
            except:
                # 解码报错问题--二进制乱码
                payload=str(payload)
            check_res=rules_op.check(icmp_rules,payload,info_data,allow_ip_list,acr)[0]
            if check_res != 0:
                drop_flag = 1
                ips_mode.drop_wirte_log(rules_op.check(icmp_rules,payload,info_data,allow_ip_list,acr)[1])
    elif tcp_layer:
        port_src = tcp_layer.sport      #提取流量源port
        port_dst = tcp_layer.dport      #提取流量目的port
        info_data['port_src']=port_src
        info_data['port_dst']=port_dst
          
        #检查tcp协议
        # rules_op.check(tcp_rules,str(tcp_layer.flags),info_data,allow_ip_list,acr)

        if 'Raw' in flow:  
            payload = flow['Raw'].load
            try:
                payload=payload.decode()   
            except:
                # 解码报错问题--二进制乱码
                payload=str(payload)

            #检查所有带raw-payload的tcp协议
            # rules_op.check(tcp_rules,payload,info_data,allow_ip_list,acr)

            #检查所有tcp上层协议规则
            tcps = protocols['tcp']
            for protocol in tcps.keys():
                if protocol == 'http':
                    # http协议[配置文件端口]
                    ports= tcps[protocol].split(";")
                    if str(port_dst) in ports:
                        # http请求检测
                        check_res=rules_op.check(http_req_rules,payload,info_data,allow_ip_list,acr)[0]
                        if check_res != 0:
                            drop_flag = 1
                            ips_mode.drop_wirte_log(rules_op.check(http_req_rules,payload,info_data,allow_ip_list,acr)[1])
                    elif str(port_src) in ports:
                        # http响应检测
                        check_res=rules_op.check(http_resp_rules,payload,info_data,allow_ip_list,acr)[0]
                        if check_res != 0:
                            drop_flag = 1
                            ips_mode.drop_wirte_log(rules_op.check(http_resp_rules,payload,info_data,allow_ip_list,acr)[1])
                elif protocol == 'mysql':
                    # mysql协议[配置文件端口]
                    ports= tcps[protocol].split(";")
                    if str(port_src) in ports:
                        # mysql响应检测
                        check_res=rules_op.check(mysql_resp_rules,payload,info_data,allow_ip_list,acr)[0]
                        if check_res != 0:
                            drop_flag = 1
                            ips_mode.drop_wirte_log(rules_op.check(mysql_resp_rules,payload,info_data,allow_ip_list,acr)[1])
                    elif str(port_dst) in ports:
                        # mysql请求检测
                        check_res=rules_op.check(mysql_req_rules,payload,info_data,allow_ip_list,acr)[0]
                        if check_res != 0:
                            drop_flag = 1
                            ips_mode.drop_wirte_log(rules_op.check(mysql_req_rules,payload,info_data,allow_ip_list,acr)[1])
                elif protocol == 'ssh':
                    # ssh协议[配置文件端口]
                    ports= tcps[protocol].split(";")
                    if str(port_dst) in ports:
                        # ssh请求检测--原始流量
                        # print(bytes_hex(flow))
                        check_res=rules_op.check(ssh_rules,str(bytes_hex(flow)),info_data,allow_ip_list,acr)[0]
                        if check_res != 0:
                            drop_flag = 1
                            ips_mode.drop_wirte_log(rules_op.check(ssh_rules,str(bytes_hex(flow)),info_data,allow_ip_list,acr)[1])
                elif protocol == 'redis':
                    ports= tcps[protocol].split(";")
                    if str(port_dst) in ports:
                        # redis请求检测
                        check_res=rules_op.check(redis_rules,payload,info_data,allow_ip_list,acr)[0]
                        if check_res != 0:
                            drop_flag = 1
                            ips_mode.drop_wirte_log(rules_op.check(redis_rules,payload,info_data,allow_ip_list,acr)[1])

    elif udp_layer:
        port_src = udp_layer.sport      #提取流量源port
        port_dst = udp_layer.dport      #提取流量目的port
        info_data['port_src']=port_src
        info_data['port_dst']=port_dst
        #检查所有udp上层协议规则
        udps = protocols['udp']
        for protocol in udps.keys():
            if protocol == 'dns':
                # dns协议[配置文件端口]
                ports= udps[protocol].split(";")
                if str(port_dst) in ports:
                    #DNS请求类型
                    #[1, 28, 12]:  A AAAA PTR   [16, 15, 5, 10]: TXT MX CNAME NULL
                    query_type=str(flow['DNS'].qd.qtype)
                    check_res1=rules_op.check(dns_rules,query_type,info_data,allow_ip_list,acr)[0]
                    #DNS请求域名
                    query_domain=flow['DNS'].qd.qname.decode()
                    check_res2=rules_op.check(dns_rules,query_domain,info_data,allow_ip_list,acr)[0]
                    if check_res1 != 0:
                        drop_flag = 1
                        ips_mode.drop_wirte_log(rules_op.check(dns_rules,query_type,info_data,allow_ip_list,acr)[1])
                    if check_res2 != 0:
                        drop_flag = 1
                        ips_mode.drop_wirte_log(rules_op.check(dns_rules,query_domain,info_data,allow_ip_list,acr)[1])

    if drop_flag == 1:
        pkt.drop()
    else:
        pkt.accept()

try:
    # 读取配置文件
    config = json.load(open("config.json"))
    filter_op = config["filter"]
    protocols = config["protocol_port"]
    # acr配置和nfq配置
    acr = config["ActiveResponse"]
    nfq = config["netfilterqueue"]
    # 白名单ip
    allow_ip = config["allow_ip"]
    allow_ip_list = allow_ip["ip_list"].split(",")
    print("配置文件加载成功")
except:
    print("配置文件加载失败,启动失败\n")
    exit(1)

try:
    # 读取规则
    rulefiles = config['rulefiles']
    # 检查id唯一性
    all_id = rules_op.get_all_id(rulefiles)
    print("检查规则id是否重复")
    if len(all_id) != len(set(all_id)):
        print("存在重复id:")
        # 列表推导式,提取重复id
        repeat_id = set([x for x in all_id if all_id.count(x) > 1])
        for id in repeat_id:
            print(id)
        exit(1)
    else:
        print("规则id无重复,开始加载规则文件")
    # 加载规则文件
    tcp_rules = json.load(open(rulefiles['tcp']))
    icmp_rules = json.load(open(rulefiles['icmp']))
    http_req_rules = json.load(open(rulefiles['http_req']))
    http_resp_rules = json.load(open(rulefiles['http_resp']))
    mysql_req_rules = json.load(open(rulefiles['mysql_req']))
    mysql_resp_rules = json.load(open(rulefiles['mysql_resp']))
    ssh_rules = json.load(open(rulefiles['ssh']))
    redis_rules = json.load(open(rulefiles['redis']))
    dns_rules = json.load(open(rulefiles['dns']))
    print("规则文件加载成功")
except:
    print("规则文件加载失败,启动失败\n")
    exit(1)

if allow_ip["is_set"] != 'yes':
    allow_ip = input("白名单主机未初始化,请输入当前ids检测的白名单ip列表,ip之间用逗号分隔:\n")
    config["allow_ip"]['ip_list'] = allow_ip
    config["allow_ip"]["is_set"] = "yes"
    try:
        with open ("config.json", "w") as fp:
            json.dump(config, fp, indent=4)
            print(f"ip白名单初始化为{allow_ip},重启后生效")
    except:
        print(f"ip白名单初始化失败,启动失败\n")
        exit(2)
else:
    print("ip白名单已初始化")
    # 加载配置
    config = inter_mode.handle_arg(sys.argv[1:], config, all_id)
    if acr['status'] == "on":
        print("主动响应已开启")
    #清空缓存
    check_op.clear_check('./check.csv')
    #守护线程监控缓存大小
    th_check=threading.Thread(target=check_op.monitor_check,args=('./check.csv',50000,1800))
    # 设为守护线程
    th_check.setDaemon(True)
    th_check.start()

    if nfq['status'] == "on":
        # nfq已开启
        print("nfq已开启")
        # netfilterqueue监听
        ips_mode.open_nfq(config)
        # 创建netfilterqueue实例对象
        filter = netfilterqueue.NetfilterQueue()
        # 将监听队列0与http_handler绑定，将拦截的包传入该函数中
        filter.bind(1, do_capture_ntf)
        # 运行netfilterqueue，进行数据包拦截
        filter.run()
    elif nfq['status'] == "off":
        # 开始sniff监听
        sniff(filter=config["filter"], prn=lambda x: do_capture(x))

