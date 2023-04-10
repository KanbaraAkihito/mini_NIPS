# -*-coding:utf-8-*-
import re
import csv
import time
import json
import threading


import ips_mode

# 获取当前配置中，所有规则的id
def get_all_id(rule_files: dict) -> list:
    all_id = []
    for rule_file in rule_files.values():
        rule_dict = json.load(open(rule_file))
        for rule in rule_dict.values():
            all_id.append(int(rule['r_id']))
    all_id.sort()
    return all_id

def active_response(ip_dst: str, ip_src: str, allow_ip_list: list, logdata: list, acr: dict):
    if ip_src not in allow_ip_list:
        new_thread_in = threading.Thread(target=ips_mode.deny_ip_in,args=(logdata,ip_src,acr["timeout"]))
        new_thread_out = threading.Thread(target=ips_mode.deny_ip_out,args=(logdata,ip_src,acr["timeout"]))
        new_thread_in.start()
        new_thread_out.start()
    if ip_dst not in allow_ip_list:
        new_thread_in = threading.Thread(target=ips_mode.deny_ip_in,args=(logdata,ip_dst,acr["timeout"]))
        new_thread_out = threading.Thread(target=ips_mode.deny_ip_out,args=(logdata,ip_dst,acr["timeout"]))
        new_thread_in.start()
        new_thread_out.start()

def write_log(logfile,data):
    #追加写CSV日志
    with open(logfile,'a',newline='') as fp:
        writer = csv.writer(fp)
        writer.writerow(data)

def write_alert_log(logfile,data):
    #追加写log预警日志
    fp=open(logfile,mode='a')
    fp.write(data+'\n')
    fp.close()

def read_log_num(logfile,freq_time,r_id,ip_src,ip_dst,freq_noalert):
    #读取阈值时间内，is_hit为0的r_id次数
    num = 0
    with open(logfile) as fp:
        loginfos=csv.DictReader(fp)
        for info in loginfos:
            logtime = info['logtime']
            rule_id = info['r_id']
            is_hit = info['is_hit']
            ipsrc = info['ip_src']
            ipdst = info['ip_dst']
            iplis=[ipsrc,ipdst]
            timearray = time.strptime(logtime,"%Y-%m-%d %H:%M:%S")
            logtime = time.mktime(timearray)
            nowtime = time.time()
            if rule_id == r_id and is_hit == "1" and logtime > nowtime-float(freq_noalert) and ip_src in iplis and ip_dst in iplis:
                num=-1
                break
            elif logtime > nowtime-float(freq_time) and rule_id == r_id and ip_src in iplis and ip_dst in iplis and is_hit == "0":
                num = num+1
    return num

def read_log_match(logfile,r_id,ip_src,ip_dst,timediff):
    #读取关联规则
    flag = False
    with open(logfile) as fp:
        loginfos=csv.DictReader(fp)
        for info in loginfos:
            logtime = info['logtime']
            ipsrc = info['ip_src']
            ipdst = info['ip_dst']
            iplis=[ipsrc,ipdst]    #可能匹配的是请求或响应，源目Ip调换
            rule_id = info['r_id']
            is_hit = info['is_hit']
            timearray = time.strptime(logtime,"%Y-%m-%d %H:%M:%S")
            logtime = time.mktime(timearray)
            nowtime = time.time()
            timediff = float(timediff)
            if nowtime-logtime < timediff and rule_id == r_id and is_hit == "1" and ip_src in iplis and ip_dst in iplis:
                flag = True
    return flag

# rules_op.py 中的check方法修改增加返回值  alert_num为alert预警规则的数量,可能触发多条预警，此时alert_num>0,只需要根据alert_num是否为0来判断包是否丢弃或放行即可
def check(rules: dict, payload: str, info: dict, allow_ip_list: list, acr: dict) -> tuple:
    alert_num = 0
    alert_msg = []
    for rule in rules.keys():
        regex_not=rules[rule]["regex_not"]
        match_flag = False
        if regex_not == "0" and len(re.findall(rules[rule]['regex'],payload,re.IGNORECASE))!=0:
            # 正向匹配成功
            match_flag = True
        elif regex_not == "1" and len(re.findall(rules[rule]['regex'],payload,re.IGNORECASE))==0:
            # 反向匹配成功
            match_flag = True

        if match_flag:
            logtime=info['logtime']
            ip_src=info['ip_src']
            ip_dst=info['ip_dst']

            r_id=rules[rule]["r_id"]
            r_level=rules[rule]['level']
            r_alert=rules[rule]['alert']
            
            try:
                r_alert=r_alert.decode('unicode_escape')     #解决修改了rulejson规则unicode编码问题
            except:
                r_alert=rules[rule]['alert']

            logdata=[]    #日志内容
            logdata.append(logtime)
            logdata.append(r_id)
            logdata.append(r_level)
            logdata.append(r_alert)
            logdata.append(ip_src)
            if "port_src" in info.keys():
                logdata.append(info['port_src'])
                port_src=info['port_src']
            else:
                logdata.append("")
                port_src=""
            logdata.append(ip_dst)
            if "port_dst" in info.keys():
                logdata.append(info['port_dst'])
                port_dst=info['port_dst']
            else:
                logdata.append("")
                port_dst=""

            alert_flag = 5   #只要不是0或者1都行，可以是其他任意大于0的整数

            match_id = rules[rule]['match_id']
            match_time = rules[rule]['match_time']
            if len(match_id) != 0:
                # 如果设置了关联id字段
                if read_log_match('./check.csv',match_id,ip_src,ip_dst,match_time):
                    # print(r_id,'关联到',match_id)
                    alert_flag = 1
                else:
                    alert_flag = -1

            freq_num = rules[rule]['freq_num']
            freq_time = rules[rule]['freq_time']
            freq_noalert = rules[rule]['freq_noalert']
            if len(freq_num) != 0 and len(freq_time) != 0 and len(freq_noalert) != 0:
                #如果设置了频率字段
                num = read_log_num('./check.csv',freq_time,r_id,ip_src,ip_dst,freq_noalert)
                if num == int(freq_num)-1:
                    #记录日志且预警
                    alert_flag = 1
                elif num == -1:
                    #freq_noalert时间内以预警过一次，不记录也不预警
                    alert_flag = -1
                elif num == 0 and alert_flag == -1 :
                    alert_flag = -1
                else:
                    #记录日志但不预警
                    alert_flag = 0

            do_alert = rules[rule]['do_alert']
            # 如果没有match_id也没有freq_num，此时alert_flag = 5，也要记录并预警
            if alert_flag > 0:
                #记录日志且预警
                if do_alert == "1":
                    alert_msg = f"{logtime}  [id:{r_id}|level:{r_level}]  {r_alert}  {ip_src}:{port_src}<->{ip_dst}:{port_dst}"
                    # 前台输出预警日志
                    print(alert_msg)
                    # 将预警信息写入alert.log文件
                    write_alert_log('./alert.log',alert_msg)
                    # return 预警flag+1
                    alert_num = alert_num+1
                    # 在这里通过r_level进行主动响应
                    if acr["status"] == "on" and int(r_level) >= int(acr["level"]) :
                        active_response(ip_dst,ip_src,allow_ip_list,logdata,acr)
                logdata.append("1")
                write_log('./check.csv',logdata)
            elif alert_flag == 0:
                #记录日志但不预警
                logdata.append("0")
                write_log('./check.csv',logdata)
            # else:
                #alert_flag == -1的情况，不记录也不预警
                # print('不再记录也不预警')
    return alert_num,alert_msg

