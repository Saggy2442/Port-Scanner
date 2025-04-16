import re
from scapy.all import *

try:
  host = input("Enter the host to scan: ")
  p = list(input("Enter the ports to scan: ").split(","))
  temp = map(int, p)
  ports = list(temp)

  if(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host)):
    print("\n\nScanning...")
    print("Host: ", host)
    print("Ports: ", ports)

    ans,unans = sr(IP(dst=host)/TCP(dport=ports, flags="S"), timeout=2, verbose=0)

    for (s,r) in ans:
      print("[+] {} Open".format(s[TCP].dport))

except (ValueError, RuntimeError, TypeError, NameError):
  print("[-] Some Error Occured")
  print("[-] Exiting...")