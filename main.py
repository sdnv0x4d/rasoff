import nmap
import json
import subprocess
import re
import threading
from loguru import logger
import csv

rac_client = "./rac_binaries/8.3.18.1741/rac"
ras_targets = []
ras_uuid = []
ras_host = []
ras_port = ":1545"
logger.info = logger.info

targets = str(input("Введите через пробел диапазоны сетей/адреса хостов для сканирования: "))

nm = nmap.PortScanner()
outnm = nm.scan(hosts=targets, arguments='--open -n', ports='1545')
out_str = json.dumps(outnm)
out_dict = json.loads(out_str)
ras_targets.extend(out_dict['scan'])

def split_text(s: str, splitter=":"):
    return {i.split(splitter)[0].strip(): i.split(splitter)[1].strip() for i in s.split("\n") if splitter in i}

def ras_exec(re_command):
    global rac_client
    proc = subprocess.Popen(rac_client+" "+re_command,
                            stdout = subprocess.PIPE,
                            stderr = subprocess.PIPE,
                            shell = True)
    (output, err) = proc.communicate()
    if err:
        logger.error("Ошибка "+err.decode()+" при выполнении "+rac_client+" "+re_command)
        return ""
    else:
        return output.decode()

for ras_target in ras_targets:
        out_clusters = ras_exec("cluster list "+ras_target+ras_port)
        finded_clusters = (split_text(out_clusters))
        print(finded_clusters)
        ras_uuid=(finded_clusters["cluster"])
        ras_host=(finded_clusters["host"])
        
        with open('test.csv', 'w') as csvfile:
             writer = csv.DictWriter(csvfile, finded_clusters.keys())
             writer.writerow(finded_clusters)

# class grab_thread(threading.Thread):                                                                                    # поток для сбора данных по кластеру

#     def __init__(self, uuid, name, port):
#         try:
#             threading.Thread.__init__(self)
#             self.ras_server_uuid            =   uuid
#             self.thread_ras_server_host     =   name
#             self.thread_ras_port            =   port

#             self.cache_infobases            =   ""                                                                      # кэш ИБ 1С
#             self.cache_processes            =   ""                                                                      # кэш процессов 1С
#             self.cache_users                =   ""                                                                      # кэш пользователей 1С
#             self.cache_apps                 =   ""                                                                      # кэш приложений 1С
#             self.cache_hosts                =   ""                                                                      # кэш ПК пользователей
#             self.cache_licenses             =   ""                                                                      # кэш лицензий

#         except Exception as e:
#             logger.info(str(e))
#         print(type(self.ras_server_uuid))
#         print(self.ras_server_uuid)

#     def run(self):
#         global start_time

#         # получаем все необходимые данные от кластера 1С
#         infobases = ras_exec("infobase summary list --cluster="+self.ras_server_uuid+" "+ras_connect+" "+ras_target)    # Получаем список информационных баз кластера
#         processes = ras_exec("process list --cluster="+self.ras_server_uuid+" "+ras_connect)             # Получаем список процессов кластера
#         users = ras_exec("session list --cluster="+self.ras_server_uuid+" "+ras_connect)             # Получаем список сеансов
#         lics = ras_exec("session list --licenses --cluster="+self.ras_server_uuid+" "+ras_connect)  # Получаем список лицензий для сессий

#         print (infobases)
#         # заполняем кэши данных
#         for infobase in infobases:    
#             print()                                                                          # кэш информационных баз
#             self.cache_infobases    +=  "id="+str(infobase[0])+"@uuid="+str(infobase[1])+";"                    # кэш информационных баз

#         for process in processes:                                                                               # кэш процессов
#             c_pid                   =   "NULL" if str(process[2])=="None" else str(process[2])
#             self.cache_processes    +=  "id="   +str(process[0])+ \
#                                         "@uuid="+str(process[1])+ \
#                                         "@pid=" +c_pid+";"                                            #

#         for user in users:                                                                                      # кэш пользователей
#             self.cache_users        +=  "id="+str(user[0])+"@name="+str(user[1])+";"                            # кэш пользователей

#         # for host in hosts:                                                                                      # кэш ПК
#         #     self.cache_hosts        +=  "id="+str(host[0])+"@name="+str(host[1])+";"                            # кэш ПК

#         # for app in apps:                                                                                        # кэш приложений
#         #     self.cache_apps         +=  "id="+str(app[0])+"@name="+str(app[1])+";"                              # кэш приложений

#         for lic in lics:                                                                                        # кэш лицензий
#             self.cache_licenses     +=  "id="   +str(lic[0])+\
#                                     "@name='"+str(lic[1])+"'"+\
#                                     "@type='"+str(lic[2])+"'"+\
#                                     "@max='" +str(lic[3])+";"                                               # кэш лицензий

#         print(self.cache_infobases,
#               self.cache_processes,
#               self.cache_users,
#               self.cache_apps, 
#               self.cache_hosts,
#               self.cache_licenses)

# try:
#     logger.info("Process started")
#     threads = []                                                                      # массив с потоками для каждого из RAS_кластеров
#     for ras_target in ras_targets:
#         out_clusters = ras_exec("cluster list "+ras_target+ras_port)
#         finded_clusters = (split_text(out_clusters))
#         ras_uuid=(finded_clusters["cluster"])
#         ras_host=(finded_clusters["host"])

#         ras_server_uuid = ras_uuid
#         ras_server_name = ras_host
        
#         threads.append(grab_thread(ras_server_uuid, ras_server_name, ras_port))                                             # создаём новый поток в массиве потоков
#         threads[-1].start()                                                                                             # запускаем поток сбора данных
# except Exception as e:
#     logger.error(str(e))