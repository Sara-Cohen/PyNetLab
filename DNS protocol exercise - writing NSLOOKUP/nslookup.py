from scapy.all import *


def print_server(dns_resp):
    print(f"Server:  {socket.gethostbyaddr(dns_resp[IP].src)[0]}")
    print(f"Address: {dns_resp[IP].src}")
    print()


# default_path = os.path.expanduser("~")
# print(default_path + '>')
ip_list = []


def nslookup(domain, type):
    """
    Perform DNS lookup based on the provided type.

    Args:
        domain: Domain name or IP address to lookup.
        type: Type of DNS lookup ('-type=A' for A record lookup, '-type=PTR' for PTR record lookup).
    """
    try:
        socket.gethostbyaddr('8.8.8.8')[0]
        # this row is to check connect to internet, if it fails, go to except socket.error:

        if type == '-type=A':
            # DNS A record lookup
            dns_resp = sr1(IP(dst="8.8.8.8") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain)))
            print_server(dns_resp)
            for x in range(dns_resp[DNS].ancount):
                ip_list.append(dns_resp[DNSRR][x].rdata) if not (
                        dns_resp.haslayer(DNSRR) and dns_resp[DNSRR][x].type == 5) else None
                if dns_resp[DNSRR][x].type == 5:
                    aliases_name = dns_resp[DNSRR][x].rrname.decode()
                    name = dns_resp[DNSRR][x].rdata.decode()
            if name:
                print("Non-authoritative answer:")
                print(f"Name:    {name}")
            if len(ip_list) > 1:
                print('Addresses:  ', end='')
            else:
                print('Address:  ', end='')
            print(ip_list.pop())
            for ip in ip_list:
                print('         ', ip)
            if aliases_name:
                print('Aliases:', aliases_name)

        elif type == '-type=PTR':
            # PTR record lookup
            reversed_ip = '.'.join(reversed(domain.split('.'))) + '.in-addr.arpa'
            dns_resp = sr1(IP(dst="8.8.8.8") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=reversed_ip, qtype='PTR')))
            print_server(dns_resp)
            domain_name = [dns.rdata.decode() for dns in dns_resp[DNSRR] if dns.type == 12]  # PTR type
            if domain_name:
                print(f"Name: {domain_name.pop()}")
                print(f"Address: {domain}")
    except socket.error:
        print("*** Default servers are not available")
        print("Server:  UnKnown")
        print("Address:  127.0.0.1 ")
        print()
        print(f"*** UnKnown can't find {domain}: No response from server""")
    except Exception:
        print(f"*** {socket.gethostbyaddr(dns_resp[IP].src)[0]} can't find {domain}: Non-existent domain")


if __name__ == "__main__":
    # # Get domain and type from command-line arguments
    if len(sys.argv) != 3 or not sys.argv[1].startswith("-type="):
        print(sys.argv)
        print("Usage: python nslookup.py -type=<type> <domain>")
        sys.exit(1)

    type = sys.argv[1]
    domain = sys.argv[2]
    nslookup(domain, type)
