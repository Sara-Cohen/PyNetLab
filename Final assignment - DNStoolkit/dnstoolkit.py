

"""
Final Exercise for Advanced Computer Networks Course
Submitted by:
    Name: Sara Cohen


Description:
This Python script is a DNS toolkit designed to perform various DNS-related tasks as part of the concluding task for the Advanced Computer Networks course.

The script includes functions for DNS queries (dig CAA), subdomain enumeration (dnsmap), WHOIS queries (whois),
and utility functions for internet connectivity checking and domain validation.

Usage:
python dnstoolkit.py <domain>
"""

# Import necessary libraries
import sys
import socket
import re
from scapy.all import *

# Define ANSI color codes for colored output
orange = '\033[33m'
lightblue = '\033[94m'
lightgreen = '\033[92m'
reset = '\033[0m'
yellow = '\033[93m'
underline = '\033[04m'
red = '\033[31m'

# Define functions for DNS toolkit:

# dig:
def dig(domain):
    """
    Perform a DNS query for CAA (Certificate Authority Authorization) records for the given domain.

    Args:
        domain (str): The domain for which the CAA records are to be queried.

    Returns:
        None: This function prints the CAA records found for the domain or an error message if any error occurs.

    Explanation:
        This function sends a DNS query packet to the Google Public DNS server (8.8.8.8) for CAA records of the given domain.
        It then prints the CAA records found in the response, if any.

        If no response is received or no CAA records are found, appropriate error messages are printed.
    """
    try:
        dns_query_packet = IP(dst="8.8.8.8") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain, qtype='CAA'))
        response = sr1(dns_query_packet, verbose=False, timeout=5)

        # Check if response received and has DNS resource record (RR) layer
        if response and response.haslayer(DNSRR):
            print("CAA record:")
            found_records = False
            for x in range(response[DNS].ancount):
                rdata = response[DNSRR][x].rdata
                print(f"{lightgreen}{rdata[7:].decode()}{reset}")  # Decode and print CAA record
                found_records = True
            if not found_records:
                print(f"{orange}No CAA records found.{reset}")
        else:
            print(f"{orange}No response received or no CAA records found.{reset}")
    except Exception as e:
        print(f"{orange} Error occurred during dig response:{reset}", e)


# dnsmap:
def get_dns_server(domain):
    """
        Get the DNS server responsible for the given domain.

        Args:
            domain (str): The domain for which the DNS server is to be retrieved.

        Returns:
            str or None: The address of the DNS server responsible for the domain, or None if an error occurs.

        Explanation:
            This function sends a DNS query packet to the Google Public DNS server (8.8.8.8) requesting the NS (Name Server)
            records for the given domain. It then extracts the address of the DNS server responsible for the domain
            from the DNS response.

            If any error occurs during the process, an error message is printed, and None is returned.
        """
    try:
        # Construct DNS query packet to retrieve NS records for the domain
        dns_query_packet = IP(dst="8.8.8.8") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain, qtype="NS"))

        # Send DNS query packet and receive response
        response = sr1(dns_query_packet, verbose=False, timeout=5)

        # Check if response received and has DNS resource record (RR) layer
        if response and response.haslayer(DNS):
            # Iterate over DNS response to find NS records
            for rr in response[DNS].an:
                if rr.type == 2:  # NS record type
                    # Return the  DNS server responsible for the domain
                    return rr.rdata.decode()

    except Exception as e:
        print(f"{orange}Error occurred while getting DNS server:{reset}", e)

    return None


def read_wordlist():
    try:
        unique_list = []
        with open("wordlist_TLAs.txt", 'r') as file1, open("dnsmap.h", 'r') as file2:
            wordlists1 = file1.readlines()
            wordlists2 = file2.readlines()

        # Add words from the first file that are not commented out and have length <= 20
        unique_list.extend(word.strip() for word in wordlists1 if not word.startswith('#') and len(word) <= 20)

        # Add words from the second file that have length <= 20, removing non-alphanumeric characters
        unique_list.extend(
            word.strip().replace('"', '').replace(',', '') for word in wordlists2 if
            not word.startswith('#') and not word.startswith('*') and len(word.strip()) <= 20)

        # Remove duplicates
        unique_list = list(set(unique_list))

        # Remove "//" and everything that follows it
        unique_list = [word.split("//")[0] if "//" in word else word for word in unique_list]

        # Sort the list by length first, then alphabetically
        sorted_wordlists = sorted(unique_list, key=lambda x: (len(x), x))

        # Clean each word by removing non-alphanumeric characters
        cleaned_wordlists = [''.join(char for char in word if char.isalnum()) for word in sorted_wordlists]

        return cleaned_wordlists
    except Exception as e:
        print(f"{orange}Error occurred while reading wordlist:{reset}", e)
        return None


def get_subdomain_ip(dns_server, subdomain):
    """
      Get the IP address associated with a subdomain using a specific DNS server.

      Args:
          dns_server (str): The IP address of the DNS server to use for the query.
          subdomain (str): The subdomain for which the IP address is to be retrieved.

      Returns:
          str or None: The IP address associated with the subdomain, or None if an error occurs.

      Explanation:
          This function sends a DNS query packet to the specified DNS server for the given subdomain.
          It then extracts the IP address associated with the subdomain from the DNS response.
          The function first checks if the response contains any DNS resource records (RRs).
          If there are RRs, it iterates over them and checks for A (IPv4 address) or CNAME (canonical name) records.
          - If a CNAME record is found, it resolves the canonical name to an IP address using the built-in `gethostbyname` function.
          - If an A record is found, it returns the associated IP address.

          If no response is received or no relevant DNS records are found, None is returned.
      """
    try:
        # Construct DNS query packet
        dns_query_packet = IP(dst=dns_server) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=subdomain))

        # Send DNS query packet and receive response
        response = sr1(dns_query_packet, verbose=False, timeout=5)
        # Check if response received and has DNS resource record (RR) layer
        if response and response.haslayer(DNSRR):
            if response.haslayer(DNS):
                for rr in response[DNS].an:
                    if rr.type == 5:  # CNAME record type
                        cname = rr.rdata.decode()
                        domain_ip = socket.gethostbyname(cname)
                        if not domain_ip:
                            return None
                        return domain_ip
                    elif rr.type == 1:  # A record type
                        return rr.rdata
    except Exception as e:
        print(f"{orange}Error occurred while getting subdomain{' '}{subdomain} IP:{reset}", e)
    return None


def dnsmap(domain):
    """
    Perform subdomain enumeration using wordlist and DNS queries.

    Arguments:
        domain (str): the domain for which subdomain names must be given.

    Returns:
        None: This function prints the subdomains and their corresponding IP addresses if found.

    explanation:
        This function performs subdomain enumeration for the given domain using a wordlist and DNS queries.
        It retrieves a list of possible subdomain prefixes from a wordlist file using the 'read_wordlist' function.
        It then obtains the address of the DNS server responsible for the domain using the 'get_dns_server' function.
        It then iterates through each subdomain in the word list and builds a fully qualified domain name by adding that for the resulting domain.

        For each subdomain it builds, it asks the DNS server to get its IP address using 'get_subdomain_ip'
        function. If an IP address is found, it prints the subdomain name along with its IP address.

        If any error occurs during the process, an error message is printed.

    """
    try:
        # Get a list of possible subdomains from the list of words
        subdomains = read_wordlist()
        if not subdomains:
            return
        # Get  DNS server responsible for the domain
        dns_server = get_dns_server(domain)
        if not dns_server:
            return


        my_flag = False
        # Iterate over each subdomain in the wordlist
        for subdomain in subdomains:
            # Construct full domain name by appending subdomain to the main domain
            domain_to_check = ".".join([subdomain, domain])

            # Get IP address of the subdomain using the DNS server
            ip_address = get_subdomain_ip(dns_server, domain_to_check)
            if ip_address:
                # Append subdomain and its IP address to the result table
                print(
                    f"Subdomain: {lightgreen}{subdomain}.{domain}\033[0m, IP Address: {lightgreen}{ip_address}{reset}")
                my_flag = True

        if not my_flag:
            print(f"{orange}No subdomains found for the domain:{domain}{reset}")
    except Exception as e:
        print(f"{orange}Error occurred while printing subdomain IP:{reset}", e)


# whois:
def get_tld(domain):
    """
    Get the top-level domain (TLD) from a given domain name.

    Args:
        domain (str): The domain name from which the TLD is to be extracted.

    Returns:
        str: The top-level domain (TLD) extracted from the domain name.

    Explanation:
        This function extracts the top-level domain (TLD) from a given domain name.
        It splits the domain name by '.' and retrieves the last part, which represents the TLD.
        For example, for the domain 'example.com', the TLD is 'com'.
        The extracted TLD is then returned.
    """
    parts = domain.split('.')
    tld = parts[-1]
    return tld


def get_whois_server(domain):
    """
    Get the WHOIS server for a given top-level domain (TLD).

    Args:
        domain (str): The domain name for which the WHOIS server is to be retrieved.

    Returns:
        str or None: The WHOIS server associated with the domain's top-level domain (TLD), or None if an error occurs.

    Explanation:
        This function retrieves the WHOIS server associated with the top-level domain (TLD) of a given domain name.
        It first extracts the TLD using the `get_tld` function.
        Then, it connects to the WHOIS server registry (whois.iana.org) on port 43 and sends a query for the TLD.
        Upon receiving the response, it parses the response to find the WHOIS server information.
        The WHOIS server information is extracted from the response, specifically from the line starting with "whois:".
        The WHOIS server information is then returned.

        If any error occurs during the process, an error message is printed, and None is returned.
    """
    try:
        # Extract TLD from the domain name
        tld = get_tld(domain)

        # Connect to the WHOIS server registry
        my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        my_socket.connect(("whois.iana.org", 43))
        my_socket.send((tld + '\r\n').encode())

        # Receive and process the response
        response = b""
        while True:
            data = my_socket.recv(1024)
            if not data:
                break
            response += data
        my_socket.close()

        # Parse the response to find the WHOIS server information
        lines = response.decode().split('\n')
        whois_line = None
        for line in lines:
            if line.startswith("whois:"):
                whois_line = line.strip()
                break

        # Extract the WHOIS server information from the response
        whois_variable = whois_line.split(": ")[1].replace(" ", "") if whois_line else None
        return whois_variable

    except Exception as e:
        print(f"{orange}Error occurred in get_whois_server:{reset}", e)
        return None


def my_whois_filter(packet):
    """
    Filter function to identify TCP packets related to WHOIS queries.

    Args:
        packet (scapy.packet.Packet): The packet to be filtered.

    Returns:
        bool: True if the packet is a TCP packet related to a WHOIS query, False otherwise.

    Explanation:
        This function serves as a filter to identify TCP packets that are related to WHOIS queries.
        It checks whether the packet contains both TCP and IP layers, and whether the source port of the TCP packet
        is 43, which is the well-known port for WHOIS queries.

        If the conditions are met, the function returns True, indicating that the packet is related to a WHOIS query.
        Otherwise, it returns False.

    """
    if TCP in packet and IP in packet and packet[TCP].sport == 43:
        return True
    return False


def whois(domain):
    """
    Perform a WHOIS query for the given domain.

    Args:
        domain (str): The domain for which WHOIS information is to be retrieved.

    Returns:
        None: This function prints the WHOIS information for the domain, or an error message if WHOIS server is not found or an error occurs.

    Explanation:
        This function retrieves WHOIS information for the given domain by querying the WHOIS server associated with
        its top-level domain (TLD). It first obtains the WHOIS server using the `get_whois_server` function.

        If the WHOIS server is not found, it returns an error message.

        Otherwise, it establishes a connection to the WHOIS server on port 43 and sends a WHOIS query for the domain.
        It then waits for the response using the `sniff` function with a timeout to capture WHOIS response packets.
        Upon receiving the response packets, it extracts the WHOIS information from the Raw layer of the packets.
        The WHOIS information is then returned.

        If any error occurs during the process, an error message is returned.
    """
    # Get WHOIS server for the domain
    whois_server = get_whois_server(domain)

    # Check if WHOIS server is found
    if not whois_server:
        print(f"{orange}Error: WHOIS server not found{reset}")
        return

    try:
        # Establish connection to the WHOIS server
        my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        my_socket.connect((whois_server, 43))

        # Send WHOIS query for the domain
        my_socket.sendall((domain + '\r\n').encode())

        # Capture WHOIS response packets
        packets = sniff(timeout=10, lfilter=my_whois_filter)
        whois_data = b""

        # Extract WHOIS information from the response packets
        for packet in packets:
            if packet.haslayer(Raw):
                whois_data += packet[Raw].load

        # Close the socket connection
        my_socket.close()
        # Check if WHOIS data is empty
        if not whois_data:
            print(f"{orange}No WHOIS information received from the server.{reset}")
            return

        # print WHOIS information
        print(whois_data.decode())

    except Exception as e:
        return print(f"{orange}Error:{str(e)}{reset}")


def check_internet_connection():
    try:
        # Try to resolve a well-known domain to check for internet connectivity
        socket.gethostbyname("www.google.com")
        return True
    except Exception as e:
        print(f"{orange}Error occurred while checking internet connection:{reset}", e)
        return False


def is_valid_domain(domain):
    # Basic check for a valid domain name
    # Domain format rules
    domain_regex = r'^((?!-)[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,63}$'
    # Convert domain to lowercase for consistency
    domain = domain.lower()

    # Check domain format
    if not re.match(domain_regex, domain):
        return False
    return True


def main():
    if len(sys.argv) != 2:
        print(f"{red}Usage:{reset} python dnstoolkit.py <domain>")
        sys.exit(1)

    domain = sys.argv[1]

    if not is_valid_domain(domain):
        print(f"{orange}Invalid domain name.{reset}")
        sys.exit(1)

    if not check_internet_connection():
        print(f"{orange}No internet connection.{reset}")
        sys.exit(1)

    print(f"\n{lightblue}Running DNS toolkit for domain: {reset}{domain}")
    # Perform dig
    print(f"\n{lightblue}Performing dig:{reset}")
    dig(domain)

    # Perform dnsmap
    print(f"\n{lightblue}Performing dnsmap:{reset}")
    dnsmap(domain)

    # Perform whois
    print(f"\n{lightblue}Performing whois:{reset}")
    whois(domain)


if __name__ == "__main__":
    main()
