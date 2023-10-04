#!/usr/bin/env python3

import nmap
import json
import subprocess
import re
import argparse
from loguru import logger
import pandas as pd

parser = argparse.ArgumentParser(description="1C RAS Offensive Security Tool")
parser.add_argument("-b", "--bin", type=str, default="./rac_binaries/8.3.18.1741/rac", help="Путь до исполняемого файла rac")
parser.add_argument("-r", "--range", type=str, help="Диапазоны сетей/адреса хостов для сканирования через пробел")
parser.add_argument("-u", "--username", type=str, help="Имя Пользователя кластера 1С")
parser.add_argument("-p", "--password", type=str, help="Пароль Пользователя кластера 1С")
parser.add_argument("-n", "--nmap", action="extend", nargs="+", help="Доп. Аргументы для nmap")
#parser.add_argument("-ss", "--skip-scan", type=str, help="Указание хостов пропуская сканирование nmap, через пробел")
args = parser.parse_args()

rac_client = args.bin
targets = args.range
username = args.username
password = args.password
ras_targets = []
ras_uuid = []
ras_host = []
ras_port = ":1545"

if username is not None:
    ras_connect = str(f"--cluster-user={username} ")
    if password is not None:
        ras_connect += str(f"--cluster-pwd=\"{password}\" ")

if targets is None:
    targets = str(input("Введите через пробел диапазоны сетей/адреса хостов для сканирования: "))

def nmap_1c():
    logger.info("Начало сканирования Консолей Кластера 1С в диапазоне "+targets)
    try:
        nm = nmap.PortScanner()
        outnm = nm.scan(hosts=targets, arguments='--open -n {args.nmap} ', ports='1545')     #   Сканирование указанных IP на 1545 порту
        out_str = json.dumps(outnm)
        out_dict = json.loads(out_str)
        ras_targets.extend(out_dict['scan'])
        if len(ras_targets) == 0:
            logger.error("Консоль Кластера 1С на стандартном порту 1545 в диапазоне "+targets+" не найден, выход...")
            exit()
    except Exception as e:
        logger.error(str(e))

def split_srv(s: str, splitter=":"):
    return {i.split(splitter)[0].strip():
            i.split(splitter)[1].strip()
            for i in s.split("\n")
                if splitter in i}

def split_re(s: str, pattern, splitter=":"):
    res = []
    for i_s in s.split('\n\n'):
        res.append({i.split(splitter)[0].strip():
                    i.split(splitter)[1].strip()
                    for i in i_s.split("\n")
                        if splitter in i
                            if re.search(pattern, i)
                            if i != "{}"})    # Добавление данных в список, при соответствии паттерна
    return res

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

def change_uuid_to_infobase_name(sessions_copy, infobases_name=None):
    if infobases_name is None:
        infobases_name = split_infobases

    for session in sessions_copy:
        for base in infobases_name:
            if base.get('infobase') == session.get('infobase') and base.get('infobase') is not None:
                session['infobase'] = base['name']

nmap_1c()

try:
    logger.info("Подготовка UUID и IP-адресов 1С Серверов")
    for ras_target in ras_targets:
        out_clusters = ras_exec("cluster list "+ras_target+ras_port)    #   Запуск rac для сбора информации по кластерам
        finded_clusters = (split_srv(out_clusters))
        ras_uuid=(finded_clusters["cluster"])
        ras_host=(finded_clusters["host"])

        logger.info("Начало сбора информации по информационным базам из Консоли Кластера "+ras_host)
        infobases = ras_exec("infobase summary list --cluster="+ras_uuid+" "+ras_connect+" "+ras_target)    # Получаем список информационных баз кластера
        split_infobases = (split_re(infobases,r'(infobase|name)'))

        logger.info("Начало сбора информации по сессиям из Консоли Кластера "+ras_host)
        sessions = ras_exec("session list --cluster="+ras_uuid+" "+ras_connect+" "+ras_target)              #   Запуск rac для сбора информации по сессиям
        split_sessions = (split_re(sessions,r'(infobase\s|user-name\s|host\s|app-id\s|started-at\s|last-active-at\s|client-ip\s)'))

        csv_name = ras_host + ".csv"
        sessions_with_names = split_sessions.copy()
        change_uuid_to_infobase_name(sessions_with_names)
        df = pd.DataFrame(sessions_with_names)
        check_df = df.head(1)                                               #    Чтение первой строки в DataFrame
        if check_df.empty == True:                                          ##   Проверка наличия записей в DataFrame
            logger.error("Данные в Консоли "+ras_target+" отсутствуют")     ##
        else:                                                               #
            logger.info("Создание .csv файла "+ras_host)                    #
            df.to_csv(csv_name, sep=',')                                    #    Запись DataFrame в .csv файл

except Exception as e:
    logger.error(str(e))
