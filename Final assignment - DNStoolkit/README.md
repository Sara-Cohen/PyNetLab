## DNStoolkit

### Final Assignment - Advanced Computer Networks Course

---

### Description:

This Python script serves as a DNS toolkit designed for the final assignment of the Advanced Computer Networks course. It includes functions to perform various DNS-related tasks such as DNS queries, subdomain enumeration, and WHOIS queries.

---

### Instructions:

1. **Usage**:
   - Run the script with the domain as a command-line argument:
     ```bash
     python dnstoolkit.py <domain>
     ```

2. **Required Installations**:
   - Python 3.x
   - Scapy

3. **Query Process**:
   - **dig (DNS query for CAA records)**:
     - The script performs a DNS query for CAA (Certificate Authority Authorization) records of the given domain.
   - **dnsmap (Subdomain Enumeration)**:
     - Subdomain enumeration is conducted using a custom wordlist and DNS queries. The script sends DNS queries for each possible subdomain derived from the wordlist to map out existing servers and their IP addresses.
   - **WHOIS (Domain Registration Information)**:
     - The script retrieves WHOIS information for the given domain. It first identifies the WHOIS server associated with the domain's top-level domain (TLD). Then, it establishes a connection to the WHOIS server and sends a WHOIS query for the domain. Finally, it captures and prints the WHOIS information received from the server.

---

### How to Operate:

1. **Running the Script**:
   - Ensure Python 3.x and Scapy are installed.
   - Execute the script with the desired domain as an argument. It will perform all the necessary queries in one go.

---

### Solution Files:

- **dnstoolkit.py**: Python script containing the DNS toolkit functions.
- **dnsmap.h**: Wordlist file used for DNS enumeration.
- **wordlist_TLAs.txt**: Another wordlist file used for DNS enumeration.

---

### Notes:

- Internet connectivity is required for DNS queries and WHOIS lookups.
- This script is intended for educational purposes only and should be used responsibly.

---