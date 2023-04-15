# mini_NIPS
用python写的一个nips，实现了较为完备的功能


NIDS-帮助


启动参数：
-I 交互配置模式，可以一定程度修改配置文件，增加删除规则等，重启后持久生效
-F 指定过滤条件(仅对当次运行生效，遵循BPF语法)
-A 开主动响应模式运行(仅对当次运行生效)
-N 开启NFQ模式运行(默认支持http,mysql.redis.ssh.dns,icmp异常流量的检测和拦截)


规则说明：
在./rules/目录中存放了规则的json文件，每个文件对应种协议
其中，规则字段是固定且通用的，如下述这个例子：
```json
"rule_name": {
    "r_id": "1",
    "level": "5",
    "regex": "http/1.1\\s*404\\s*not\\s*found",
    "regex_not": "0",
    "alert": "触发规则ID:1,连续出现404响应，疑似扫描",
    "do_alert": "1",
    "match_id": "", 
    "match_time": "",                 
    "freq_num": "5",                
    "freq_time": "20",   
    "freq_noalert": "60",            
    "check_info": "404扫描规则"
  }
```

```
-- "rule_name" 是该规则的名称，不建议重复
-- "r_id"的值为该规则的id，要求在所有规则文件中全局唯一
-- "level"的值为该规则的预警等级
-- "regex"的值为该规则的正则匹配内容，应为正确的正则表达式
-- "regex_not"的值标识了匹配正则时是否反向匹配，默认为0，表示不进行反向匹配，置为1时表示进行反向匹配
-- "alert"的值为该规则触发预警时的报警信息
-- "do_alert"的值标识了该规则命中时是否报警，默认为1，表示报警，置为0时表示不报警
-- "match_id"的值为该规则的前置规则id，默认为空，表示没有前置规则
-- "match_time"的值为该规则的前置规则有效时间段，单位为秒，默认为空，仅当match_id不为空时，该字段才有效
-- "freq_num"的值为该规则阈值预警次数，默认为空，表示不进行阈值预警
-- "freq_time"的值为该规则阈值预警时间段，单位为秒，默认为空
-- "freq_noalert"的值为该规则阈值预警静默时间，单位为秒，默认为空
-- "check_info"的值是该规则的描述信息
```

注意：
match_time必须在match_id有效时才有效
freq_num，freq_time， freq_noalert必须都有值时，才会生效


配置文件说明：
配置文件为./config.json。包含了sniff的过滤信息，规则文件信息，主动响应的相关配置，内置协议对相应的端口列表，白名单ip列表。
其中，白名单ip列表需要在第一次启动时进行初始化配置，被添加进白名单的ip将不受ips模块的限制





详细的功能演示，请查看DEMO.pdf
