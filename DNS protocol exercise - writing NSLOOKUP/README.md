
# PyNetLab - DNS Protocol Exercise: Writing NSLOOKUP

PyNetLab's "DNS Protocol Exercise: Writing NSLOOKUP" involves writing a script in Python that performs DNS lookup based on the provided type. The script accepts a domain address from users and prints its corresponding IP address(es). Additionally, if a canonical name (CNAME) is received, it prints the CNAME as well. The script also supports reverse mapping functionality, allowing users to perform reverse DNS lookup.

## Solution Overview

The solution includes a Python script named `nslookup.py` that utilizes the Scapy library for DNS query and response handling.

### Solution Files:

- **nslookup.py**: Python script that performs DNS lookup based on the provided type (`-type=A` for A record lookup, `-type=PTR` for PTR record lookup).
- **Requirements**: Scapy library.

## Installation and Usage

### Requirements

- Python 3.x
- Scapy library (`scapy`)

### Installation

1. Install the Scapy library using pip:
   ```
   pip install scapy
   ```

### Running the Script

1. Open a terminal.
2. Navigate to the directory containing the solution files.
3. Run the following command to execute the script:
   ```
   python nslookup.py -type=<type> <domain>
   ```
   Replace `<type>` with `-type=A` for A record lookup or `-type=PTR` for PTR record lookup.
   Replace `<domain>` with the domain address or IP address to lookup.

#### Example Usages:

- A record lookup:
  ```
  python nslookup.py -type=A www.example.com
  ```

- PTR record lookup:
  ```
  python nslookup.py -type=PTR 8.8.8.8
  ```

## Additional Notes

- The script utilizes Scapy's DNS query functionality to perform DNS lookup.
- Reverse mapping support is provided for reverse DNS lookup using the `-type=PTR` parameter.
