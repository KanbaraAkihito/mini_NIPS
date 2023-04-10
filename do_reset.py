# -*-coding:utf-8-*-

import json
import os

def reset_config():
    default_config = {
        "filter": "tcp or udp or icmp",
        "rulefiles": {
            "icmp": "./rules/icmp.json",
            "tcp": "./rules/tcp.json",
            "http_req": "./rules/http_req.json",
            "http_resp": "./rules/http_resp.json",
            "mysql_req": "./rules/mysql_req.json",
            "mysql_resp": "./rules/mysql_resp.json",
            "ssh": "./rules/ssh.json",
            "redis": "./rules/redis.json",
            "dns": "./rules/dns.json"
        },
        "ActiveResponse": {
            "status": "off",
            "level": "8",
            "timeout": "60"
        },
        "protocol_port": {
            "tcp": {
                "http": "80;8080;8888",
                "mysql": "3306",
                "ssh": "22",
                "redis": "6379"
            },
            "udp": {
                "dns": "53"
            }
        },
        "allow_ip": {
            "is_set": "no",
            "ip_list": "127.0.0.1"
        }
    }

    current_config = json.load(open("./config.json"))

    try:
        with open("./config.json.back", "w") as fp:
            json.dump(current_config, fp, indent=4)
    except:
        print("备份当前配置文件失败")
        exit()

    try:
        with open("./config.json", "w") as fp:
            json.dump(default_config, fp, indent=4)
            print("重置配置文件成功:./config.json\n\n")
            os.system("rm -rf config.json.back")
    except:
        print("重置配置文件失败")
        print("当前配置文件的备份文件为:./config.json.back\n\n")
        exit()

if __name__ == '__main__':
    reset_config()