from scapy.all import ARP, sniff, getmacbyip, Ether, srp

def get_mac(ip):
    # Enviar una solicitud ARP para obtener la dirección MAC de una IP
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    if answered_list:
        return answered_list[0][1].hwsrc
    return None

def detect_arp_spoof(router_ip):
    router_mac = get_mac(router_ip)
    if not router_mac:
        print("Error: No se pudo obtener la dirección MAC del router.")
        return

    print(f"MAC del router verdadero: {router_mac}")

    def process_packet(packet):
        if packet.haslayer(ARP) and packet[ARP].op == 2:
            print(f"Paquete ARP detectado: {packet.summary()}")
            try:
                real_mac = get_mac(packet[ARP].psrc)
                response_mac = packet[ARP].hwsrc

                if real_mac != response_mac:
                    print(f"[*] Posible ARP Spoofing detectado de IP {packet[ARP].psrc}!")
                    print(f"Dirección MAC real: {real_mac}, Dirección MAC falsa: {response_mac}")
                else:
                    print(f"[+] ARP Response de {packet[ARP].psrc} es legítima.")
            except IndexError:
                pass

    print("Iniciando la detección de ARP Spoofing...")
    sniff(store=False, prn=process_packet, filter="arp")

if __name__ == "__main__":
    router_ip = input("Ingrese la IP del router: ")
    detect_arp_spoof(router_ip)
