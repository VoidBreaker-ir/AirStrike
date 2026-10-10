import os
import json
import subprocess
import platform
try:
    import tabulate
except ImportError:
    pass

class Saved_AP:
    def __init__(self):
        self.AP = {}
        self.status = False 

    def _run_code(self, text , timeout) -> str:
        try:
            result = subprocess.run(
                text,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            output = result.stdout + result.stderr
            
            return output
            
        except subprocess.TimeoutExpired:
            return f"Error: The command did not complete after {timeout} seconds"
        except Exception as e:
            return f"Error executing command: {e}"         

    def _check(self):
        if not self.status:
            self.start()        

    def linux(self):
        path = r'/etc/NetworkManager/system-connections'
        listdir = os.listdir(path)        
        for file in listdir:
            ssid = file.replace(".nameconnection", '')
            with open(os.path.join(path,file)) as f:
                    lines = f.readline()
                    for line in lines:
                         if line.startswith("psk="):
                              password = line[4:].strip('\n')
                              self.AP[ssid] = password
                              break
        self.status = True                         

    def windows(self, timeout = 10):
        output = self._run_code("netsh wlan show profiles", timeout=timeout)
        output = output.split('\n')
        for line in output:
            line = line.strip()            
            if line.startswith("All User Profile"):
                ssid = line.split(":")[1].strip()
                output2 = self._run_code(f"netsh wlan show profiles name={ssid} key=clear", timeout=timeout)
                output2 = output2.split('\n')
                for line in output2:
                    line = line.strip()
                    if line.startswith("Key Content"):
                        passowrd = line.split(":")[1]
                        self.AP[ssid] = passowrd
        self.status = True

    def save(self, namefile : str, *args , **kwargs):
        self._check()
        with open(namefile, 'w') as file:
            json.dump(self.AP, file, *args, **kwargs)

    def list_AP(self):
        self._check()
        AP = []
        for ssid, password in self.AP.items():
            AP.append((ssid, password))
        return AP

    def tabulate(self, tablefmt : str = "rounded_grid", *args, **kwargs):
        self._check()
        headers = ["SSID", "Password"] ; rows = []
        for ssid, password in self.AP.items():
            rows.append([ssid, password])
        table = tabulate.tabulate(rows , headers , *args, tablefmt=tablefmt, **kwargs)
        return table

    def start(self):
        system = platform.system()
        if system == "Windows":
            self.windows()
        elif system == "Linux":
            self.linux()
        else:
            raise ValueError
        return self.AP


if __name__ == "__main__":
    s = Saved_AP()
    print(s.tabulate())
    print(s.save(r"D:\oo\_python\network\file.json", indent = 4))