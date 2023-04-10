# -*-coding:utf-8-*-

import json
import getopt
import do_reset

def handle_arg(argv, config_file: dict, all_id: list):
    try:
        opts, args = getopt.getopt(argv, "HIF:NA", ["help", "interactive", "filter="])
    except getopt.GetoptError:
        print("Error: 参数错误，请使用-H或--help查看帮助")
        exit()
    for opt, arg in opts:
        if opt in ("-H", "--help"):
            fp = open('help.txt')
            help_lines = fp.readlines()
            for help_line in help_lines:
                print(help_line)
            fp.close()
            exit()
		# 交互模式
        elif opt in ("-I", "--interactive"):
            while True:
                menu(config_file, all_id)
		# 指定过滤条件
        elif opt in ("-F", "--filter"):
            config_file['filter'] = arg
        # 开启nfq
        elif opt in ("-N"):
            config_file["netfilterqueue"]["status"] = "on"
		# 开启主动响应
        elif opt in ("-A"):
            config_file['ActiveResponse']['status'] = "on"
    return config_file

def menu(config_file: dict, all_id: list):
    print("------------------------------------")
    print("------------NIDS交互模式------------")
    print("")
    print("-----你可以在这里进行交互式配置-----")
    print("---------重新启动NIDS生效-----------")
    print(" ")
    print("****************注意****************")
    print("***错误的配置会导致程序无法正常启动***")
    print("如果无法正常启动,请执行reset.py重置配置")
    print("************************************")
    print(" ")
    print("1.修改过滤条件")
    print("2.开启主动响应")
    print("3.关闭主动响应")
    print("4.添加规则")
    print("5.删除规则")
    print("6.恢复初始配置")
    print("7.修改协议端口")
    print("8.修改ip白名单")
    print("9.退出")
    print("------------------------------------")
    
    option = input("请输入你的选项:\n")
    if option == '1' :
        change_filter(config_file)
    elif option == '2' :
        open_active_res(config_file)
    elif option == '3' :
        close_active_res(config_file)
    elif option == '4' :
        edit_rule_menu(config_file,"add",all_id)
    elif option == '5' :
        edit_rule_menu(config_file,"del",all_id)
    elif option == '6':
        do_reset.reset_config()
    elif option == "7":
        change_ports(config_file)
    elif option == "8":
        edit_allow_ip(config_file)
    elif option == '9':
        exit()
    else :
        print('选项错误')

def change_filter(config_file: dict):
    filter_op = input("请输入filter参数, 请使用BPF语法(https://blog.csdn.net/LngZd/article/details/114941978):\n")
    config_file['filter'] = filter_op
    try:
        with open ('./config.json', 'w') as fp:
            json.dump(config_file , fp, indent=4)
            print(f"修改成功, 当前filter为{filter_op}, 重启后生效")
    except:
        print("修改失败，写入文件错误")
        pass

def open_nfq(config_file: dict):
    config_file['NetfilterQueue']['status'] = "on"
    try:
        with open ('./config.json', 'w') as fp:
            json.dump(config_file , fp, indent=4)
            print("修改nfq配置成功: 已开启，重启后生效")
    except:
        print("修改nfq配置失败")
        pass

def close_nfq(config_file: dict):
    config_file['NetfilterQueue']['status'] = "off"
    try:
        with open ('./config.json', 'w') as fp:
            json.dump(config_file , fp, indent=4)
            print("修改nfq配置成功: 已关闭，重启后生效")
    except:
        print("修改nfq配置失败")
        pass

def open_active_res(config_file: dict):
    config_file['ActiveResponse']['status'] = "on"
    try:
        with open ('./config.json', 'w') as fp:
            json.dump(config_file , fp, indent=4)
            print("修改主动响应配置成功, 已开启，重启后生效")
    except:
        print("修改主动响应配置失败")
        pass

def close_active_res(config_file: dict):
    config_file['ActiveResponse']['status'] = "off"
    try:
        with open ('./config.json', 'w') as fp:
            json.dump(config_file , fp, indent=4)
            print("修改主动响应配置成功，已关闭，重启后生效")
    except:
        print("修改主动响应配置失败")
        pass

def edit_rule_menu(config_file: dict, opt: str, all_id: str):
    file_list = config_file['rulefiles']
    rule_type = file_list.keys()
    rule_path = file_list.values()
    if opt == "add":
        while True:
            print('当前配置中，有如下规则文件')
            for (key, val) in file_list.items():
                print(f'规则"{key}":{val}')
            add_to = input("请输入要添加规则的规则文件路径(Q退出):\n")
            if add_to in ("Q", "q"):
                print("已退出修改规则模块")
                menu(config_file,all_id)
            elif add_to not in (rule_path):
                print("配置中没有该文件,请检查输入")
            else:
                add_rule(add_to, all_id)
    if opt == "del":
        while True:
            print('当前配置中，有如下规则文件')
            for (key, val) in file_list.items():
                print(f'规则"{key}":{val}')
            del_from = input("请输入要删除规则的规则文件路径(Q退出):\n")
            if del_from in ("Q", "q"):
                print("已退出修改规则模块")
                menu(config_file,all_id)
            elif del_from not in (rule_path):
                print("配置中没有该文件,请检查输入")
            else:
                del_rule(del_from, all_id)

def add_rule(file_path: str, all_id: list):
    print(f"当前增加规则的文件:{file_path}")
    rule_file = json.load(open(file_path))

    json.dump(rule_file ,open(file_path + ".back", "w"), indent=4)
    print(f"已将当前规则文件备份至{file_path}.back")
    
    new_rule_name = input("请输入新规则的名称:\n")
    new_rule = {}

    # 基础选项
    print("请输入规则基础选项,以下各项为必填项,不能为空:\n")
    print("规则id(r_id)\n规则预警等级(level)\n规则预警信息(alert)\n规则匹配正则(regex)\n反向匹配正则标志(regex_not)\n预警标志(do_alert)\n")
    print("注意:规则id为任意整数,需要在所有规则中全局唯一")
    new_rule['r_id'] = input("请输入新规则的id(r_id):\n")
    new_rule['level'] = input("请输入规则预警等级(level):\n")
    new_rule['alert'] = input("请输入规则预警信息(alert):\n")
    new_rule['regex'] = input("请输入规则匹配正则(regex):\n")
    new_rule['regex_not'] = "0"
    new_rule['do_alert'] = "1"

    if_regex_not = input("是否进行反向正则匹配? y\n")
    if_do_alert = input("该规则是否屏蔽预警? y\n")

    if if_regex_not in ("Y", "y"):
        new_rule['regex_not'] = "1"
    if if_do_alert in ("Y", "y"):
        new_rule['do_alert'] = "0"

    # 额外选项
    new_rule['match_id'] = ""
    new_rule['match_time'] = ""
    new_rule['freq_num'] = ""
    new_rule['freq_time'] =""
    new_rule['freq_noalert'] =""
    new_rule['check_info'] = ""

    ex_op = input("是否配置可选的额外选项？ y \n")
    if ex_op in ("Y", "y"):
        print("前置规则选项(match_id)\n前置规则有效时间段(match_time)\n当前规则阈值匹配次数(freq_num)\n当前规则阈值匹配时间段(freq_time)\n当前规则阈值匹配屏蔽时间(freq_noalert)\n规则描述(check_info)")
        print("注意:\nmatch_time需要在match_id有效时才有效\nfreq_num,freq_time,freq_noalert需要在三个选项均进行配置的情况下才会生效\n")
        # 添加match_id和match_time
        match_id = input("请输入前置规则的id(match_id),如果没有前置规则,请忽视该项\n")
        if match_id != "":
            if int(match_id) not in all_id:
                print("当前配置中没有与该r_id绑定的规则,配置前置规则失败")
            elif match_id == new_rule['r_id']:
                print("不能将自身配置为前置规则")
            else:
                new_rule['match_id'] = match_id
                print(f"为当前规则{new_rule['r_id']}设定前置规则为{new_rule['match_id']}成功")
                pre_op = input("是否配置前置规则有效时间段,单位为秒(match_time)? y\n")
                if pre_op in ("Y", "y"):
                    match_time = float(input("请输入前置规则有效时间段:\n"))
                    if type(match_time) is float:
                        new_rule['match_time'] = match_time
                    else:
                        print("设置有效时间段失败")

        freq_num = input("请输入阈值匹配次数(freq_num),如果不进行阈值匹配,请忽略该项\n")
        if freq_num!="":
            new_rule['freq_num'] = freq_num
            freq_time = input(f"阈值匹配次数配置为{new_rule['freq_num']},请继续配置阈值匹配时间段(freq_time),单位为秒\n")
            try:
                freq_time = float(freq_time)
                new_rule['freq_time'] = str(freq_time)
                freq_noalert = input(f"阈值匹配时间段配置为{new_rule['freq_time']},请继续配置阈值匹配屏蔽时间(freq_noalert),单位为秒\n")
                try:
                    freq_noalert = float(freq_noalert)
                    new_rule['freq_noalert'] = str(freq_noalert)
                    print(f"阈值匹配屏蔽时间配置为{new_rule['freq_noalert']}\n")
                except:
                    print("阈值匹配屏蔽时间配置失败")
            except:
                print("阈值匹配时间段配置失败")

        check_info = input("请输入规则描述(check_info),如果不添加规则描述,请忽略该项\n")
        if check_info != "":
            new_rule['check_info'] = check_info
            print("规则描述配置成功")
            
    print(f"新规则内容如下,将添加至{file_path}:")
    print(new_rule)
    confirm = input("请确认新规则是否正确? y\n")
    if confirm in ("Y", "y"):
        rule_file[new_rule_name] = new_rule
        try:
            with open(file_path, 'w') as fp:
                json.dump(rule_file, fp, indent=4)
            print(f"成功将新规则添加至{file_path}\n\n")
        except:
            print("规则添加失败\n\n")
    else:
        print("未添加规则")

def del_rule(file_path: str, all_id: list):
    print(f"当前删除规则的文件:{file_path}")
    rule_file = json.load(open(file_path))

    json.dump(rule_file ,open(file_path + ".back", "w"), indent=4)
    print(f"已将当前规则文件备份至{file_path}.back")

    del_rule_id = input("请输入需要删除的规则id:\n")
    if int(del_rule_id) in all_id:
        for rule_name,rule in rule_file.items():
            if rule['r_id'] == del_rule_id:
                rule_file.pop(rule_name, None)
                try:
                    with open(file_path, 'w') as fp:
                        json.dump(rule_file, fp, indent=4)
                        print(f"成功删除{file_path}中,id为{del_rule_id}的规则\n\n")
                        break
                except:
                    print("删除规则失败\n\n")
    else:
        print(f"不存在id为{del_rule_id}的规则\n\n")

def change_ports(config_file: dict):
    print("请输入对应协议的端口列表,多个端口之间用;分隔\n默认支持对如下协议进行端口设置:\nhttp/tcp,mysql/tcp,ssh/tcp,redis/tcp,dns/tcp\n")
    http_ports = input("请输入http的端口列表:\n")
    mysql_ports = input("请输入mysql的端口列表:\n")
    ssh_ports = input("请输入ssh的端口列表:\n")
    dns_ports = input("请输入dns的端口列表:\n")
    redis_ports = input("请输入redis的端口列表:\n")

    http_ports_list = http_ports.split(";")
    mysql_ports_list = mysql_ports.split(";")
    ssh_ports_list = ssh_ports.split(";")
    dns_ports_list = dns_ports.split(";")
    redis_ports_list = redis_ports.split(";")

    port_error = False

    ports_list = http_ports_list + mysql_ports_list + ssh_ports_list + dns_ports_list + redis_ports_list
    for port in ports_list:
        if int(port) > 65535 or int(port) < 1:
            port_error = True
            break

    # 判断端口是否重复，以及端口号是否合法
    if len(ports_list) == len(set(ports_list)) and port_error == False:
        protocol_port = {
            "tcp": {
                "http": http_ports,
                "mysql": mysql_ports,
                "ssh": ssh_ports,
                "redis": redis_ports
            },
            "udp": {
                "dns": dns_ports
            }
        }
        if_change = input(f"新的协议端口对应关系如下:\n{protocol_port},是否确认修改? y\n")

        if if_change in ("Y", "y"):
            config_file['protocol_port'] = protocol_port
            try:
                with open("./config.json", "w") as fp:
                    json.dump(config_file, fp, indent=4)
                    print("协议端口修改成功\n")
            except:
                print("协议端口修改失败\n")
    else:
        print("出现重复端口或端口号不合法,修改协议端口失败\n")
            
def edit_allow_ip(config_file: dict):
    print(f"当前的ip白名单列表为:\n{config_file['allow_ip']['ip_list']}")
    print("请输入新的ip白名单列表,ip之间用逗号隔开\n")
    new_ip_list = input("注意:新的ip白名单会覆盖旧的ip白名单:\n")
    try:
        config_file['allow_ip']['ip_list'] = new_ip_list
        with open ('./config.json', 'w') as fp:
            json.dump(config_file , fp, indent=4)
            print("修改ip白名单成功,重启后生效")
    except:
        print("修改ip白名单失败")