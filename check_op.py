import csv
import time

# 清空缓存
def clear_check(filename):
  title=['logtime','r_id','r_level','r_alert','ip_src','port_src','ip_dst','port_dst','is_hit']
  with open(filename,'w',newline='',encoding='utf8') as fp:
    writer=csv.writer(fp)
    writer.writerow(title)

# 每sleeptime时间监控check.csv大小，超过threshold阈值行数删除旧数据
def monitor_check(filename,threshold:int,sleeptime:int):
    while True:
      title=[['logtime','r_id','r_level','r_alert','ip_src','port_src','ip_dst','port_dst','is_hit']]
      lis=[]
      with open(filename) as fp:
        res=csv.reader(fp)
        for r in res:
            lis.append(r)
      
      #检查行数是否超过阈值
      n=len(lis)
      if n > threshold:
        newlis=title+lis[n-threshold:]
        #覆盖写
        with open(filename,'w',newline='',encoding='utf8') as fp:
          writer=csv.writer(fp)
          writer.writerows(newlis)
      
      time.sleep(sleeptime)

# clear_check('./check.csv')
# monitor_check('./check.csv',50000,1800)
