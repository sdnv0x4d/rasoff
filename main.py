import nmap
import json

targets = str(input("Введите через пробел диапазоны сетей/адреса хостов для сканирования: "))
ras_targets = []

nm = nmap.PortScanner()
outnm = nm.scan(hosts=targets, arguments='--open -n', ports='1545')
out_str = json.dumps(outnm)
out_dict = json.loads(out_str)

#print(json.dumps(out_dict, sort_keys=True, indent=4))
#print(out_dict) #['scan'])

ras_targets.extend(out_dict['scan'])

for item in ras_targets:
    print (item)