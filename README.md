DIAZ SOTO CARLOS ANTONIO 6CV2
COMPUTER SECURITY
==================================
ARP Spoofing and Detección with Scapy 
==================================

This repository contains two Python scripts that allow you to perform and detect ARP Spoofing attacks on a local network using Scapy.

Requirements
----------
- Python 3
- Scapy

## Installation

**Clone the repository:**

   ```bash
   git clone <your_repository_URL>
   cd <project_directory_name>
   ```
**Install the dependencies:**

```bash
pip install -r requirements.txt
   ```

Script Execution
-------------------------
ARP Spoofing Script
----------------------
This script allows you to carry out an ARP Spoofing attack on a victim machine.

Execution:
1. Open a terminal and navigate to the directory where the `arp_spoof.py` script is located.
2. Run the script using Python 3 with administrator privileges:

```bash
sudo python3 arp_spoof.py 
```
4. You will be asked to enter the IP of the victim machine and the IP of the router.
If you do not know the IP of the router you can execute the command:
```bash
ip route | grep default
```

The output should look like:
```bash
default via 192.168.1.1 dev wlan0 proto dhcp metric 600
```

The IP that appears after default via is the IP of your router.

For the victim machine we will use nmap, we install it with the following command:
```bash
sudo apt-get install nmap
```
And we execute it in the following way
```bash
sudo map -sn "ROUTER_IP"/24  # Replace ROUTER_IP with your router's IP
```
nmap will give you a list of active devices on the network along with their IP and MAC addresses. From that list we will select our victim
		
5. The script will initiate the ARP Spoofing attack and display detailed information during execution.

Example of use:

    Ingrese la IP de la máquina víctima: 192.168.1.10
    Ingrese la IP del router: 192.168.1.1

    Iniciando ataque ARP Spoofing a 192.168.1.10
    Enviando ARP spoofing a 192.168.1.10
    ...

ARP Spoofing Detection Script
-----------------------------------
This script detects possible ARP Spoofing attacks on the network.

Execution:
1. Open another terminal and navigate to the directory where the `detect_arp_spoof.py` script is located.
2. Run the script using Python 3 with administrator privileges:
```bash
    sudo python3 detect_arp_spoof.py
```
3. You will be asked to enter the router's IP.
4. The script will start monitoring the network for suspicious ARP packets and display alerts if it detects a possible ARP Spoofing attack.

Example of use:

    Ingrese la IP del router: 192.168.1.1

    Iniciando la detección de ARP Spoofing...
    [*] Posible ARP Spoofing detectado de IP 192.168.1.10!
    Dirección MAC real: 00:11:22:33:44:55, Dirección MAC falsa: 66:77:88:99:aa:bb
    ...

