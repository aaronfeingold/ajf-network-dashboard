import os
import xml.etree.ElementTree as ET
from xml.etree.ElementTree import ParseError
import sqlite3
from datetime import datetime
import argparse

"""
Nmap XML to SQLite Database Converter

This module parses Nmap XML scan output files and imports the results into a structured SQLite database
for analysis, reporting, and dashboard integration. It provides a complete pipeline for converting
raw Nmap scan data into a queryable database format.

Key Features:
- Parses Nmap XML output files with comprehensive error handling
- Creates normalized SQLite database schema with three main tables (scans, hosts, ports)
- Extracts detailed host information including IP addresses, hostnames, and operating systems
- Captures comprehensive port data including state, protocols, and service information
- Processes Nmap script results (HTTP titles, SSL certificate details)
- Handles timestamp conversion for time-series analysis and Grafana integration
- Supports batch processing of multiple scan files

Database Schema:
- scans: Stores scan metadata (Nmap version, command line, timing, totals)
- hosts: Stores discovered host information with port statistics
- ports: Stores detailed port information with service detection results

Typical Usage:
    python nmap-to-sqlite.py --xml_file path/to/scan.xml --db_path path/to/database.db

The resulting database is optimized for:
- Network security analysis and reporting
- Integration with Grafana dashboards for visualization
- Historical scan comparison and trend analysis
- Asset discovery and inventory management

Dependencies:
- xml.etree.ElementTree: XML parsing
- sqlite3: Database operations
- argparse: Command-line interface
- datetime: Timestamp handling
"""


def parse_nmap_xml(xml_file):
    """
    Parses an Nmap XML output file and extracts relevant data for database insertion.

    Args:
        xml_file (str): Path to the Nmap XML file to be parsed.

    Returns:
        tuple: A dictionary containing scan metadata and a list of dictionaries, each representing a host's information.

    The function performs the following steps:
    1. Parses the XML structure to retrieve the scan's root element.
    2. Extracts general scan details such as:
        - Nmap version used for the scan.
        - Command-line arguments used in the scan.
        - Scan start time (in milliseconds), converting the timestamp if necessary.
    3. For each host element found in the scan:
        - Extracts the IP address, hostname (if available), and operating system (if detected).
        - Analyzes the ports section to collect information about:
            - Port numbers, protocol types, and the state of each port (open, closed, or filtered).
            - Services running on open ports, along with service name, product, version, and OS type.
            - Results from Nmap service scripts such as HTTP title and SSL certificate details.
        - If the host's OS is not detected, attempts to infer the OS based on the service OS type from open ports.
    4. Collects data related to the number of tested, open, closed, and filtered ports for each host.
    5. Returns two structures:
        - A dictionary containing overall scan metadata (e.g., version, command-line, start time).
        - A list of dictionaries, where each dictionary contains detailed information about an individual host and its ports.
    """
    tree = ET.parse(xml_file)
    root = tree.getroot()

    nmap_version = root.get('version', '')
    command_line = root.get('args', '')

    scan_start_time = root.get('start')
    if scan_start_time is None:
        # If start time is None, use current time
        scan_start_time = str(int(datetime.now().timestamp()))

    # Convert to milliseconds for Grafana
    scan_start_timestamp = int(scan_start_time) * 1000

    elapsed_time = ''
    elapsed_time_elem = root.find('runstats/finished')
    if elapsed_time_elem is not None:
        elapsed_time = elapsed_time_elem.get('elapsed')

    total_hosts = 0
    total_open_ports = 0

    hosts = []
    for host in root.findall('host'):
        total_hosts += 1
        ip = host.find('address').get('addr', '')

        hostname_elems = host.findall('hostnames/hostname')
        hostname = hostname_elems[0].get('name', '') if hostname_elems else ''

        os = 'Unknown'
        os_element = host.find('os')
        if os_element:
            os_match = os_element.find('osmatch')
            os = os_match.get('name', 'Unknown') if os_match else 'Unknown'

        ports_tested = 0
        ports_open = 0
        ports_closed = 0
        ports_filtered = 0

        ports = []
        ports_element = host.find('ports')
        if ports_element is not None:
            for port in ports_element.findall('port'):
                port_id = port.get('portid')
                protocol = port.get('protocol')
                state = port.find('state').get('state')
                if state == 'open':
                    ports_open += 1
                    total_open_ports += 1
                elif state == 'closed':
                    ports_closed += 1
                elif state == 'filtered':
                    ports_filtered += 1

                service = port.find('service')
                service_name = service.get('name', None) if service else None
                service_product = service.get('product', None) if service else None
                service_version = service.get('version', None) if service else None
                service_ostype = service.get('ostype', None) if service else None
                service_info = (service_product if service_product else '') + (' ' + service_version if service_version else '')
                http_title = None
                ssl_common_name = None
                ssl_issuer = None

                scripts = port.findall('script')
                for script in scripts:
                    if script.get('id') == 'http-title':
                        http_title = script.get('output')
                    elif script.get('id') == 'ssl-cert':
                        for table in script.findall('table'):
                            if table.get('key') == 'subject':
                                cn_elem = table.find("elem[@key='commonName']")
                                if cn_elem is not None:
                                    ssl_common_name = cn_elem.text
                            elif table.get('key') == 'issuer':
                                issuer_elems = {elem.get('key'): elem.text for elem in table.findall('elem')}
                                if 'commonName' in issuer_elems:
                                    ssl_issuer = f"{issuer_elems.get('commonName')} {issuer_elems.get('organizationName', '')}".strip()

                if service_ostype and os == 'Unknown':
                    os = service_ostype

                ports.append({
                    'port': port_id,
                    'protocol': protocol,
                    'state': state,
                    'service_name': service_name,
                    'service_info': service_info,
                    'http_title': http_title,
                    'ssl_common_name': ssl_common_name,
                    'ssl_issuer': ssl_issuer
                })

            extraports = ports_element.find('extraports')
            if len(extraports):
                extraports_count = int(extraports.get('count', '0'))
                extraports_state = extraports.get('state', '')
                if extraports_state == 'closed':
                    ports_closed += extraports_count
                elif extraports_state == 'filtered':
                    ports_filtered += extraports_count
                ports_tested += extraports_count

        host_start_time = host.get('starttime')
        host_end_time = host.get('endtime')
        start_timestamp = int(host_start_time) * 1000 if host_start_time else None
        end_timestamp = int(host_end_time) * 1000 if host_end_time else None

        hosts.append({
            'ip': ip,
            'hostname': hostname,
            'os': os,
            'ports_tested': ports_tested,
            'ports_open': ports_open,
            'ports_closed': ports_closed,
            'ports_filtered': ports_filtered,
            'start_time': start_timestamp,
            'end_time': end_timestamp,
            'ports': ports
        })

    scan = {
        'nmap_version': nmap_version,
        'command_line': command_line,
        'start_time': scan_start_timestamp,
        'elapsed_time': elapsed_time,
        'total_hosts': total_hosts,
        'total_open_ports': total_open_ports
    }

    return scan, hosts


def create_database(db_name):
    """
    Creates an SQLite database (or connects to an existing one) and sets up the required tables
    for storing Nmap scan results. The database includes tables for scans, hosts, and ports.

    Tables created:
    - scans: Stores metadata about each Nmap scan (version, command line, start time, etc.).
    - hosts: Stores information about hosts discovered during the scan, linked to the corresponding scan.
    - ports: Stores port details (status, protocol, service information) for each host.

    Args:
        db_name (str): The name (or path) of the SQLite database file to create or connect to.

    Returns:
        sqlite3.Connection: A connection object to the SQLite database.
    """
    conn = sqlite3.connect(db_name)
    c = conn.cursor()

    c.execute('''CREATE TABLE IF NOT EXISTS scans
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 nmap_version TEXT,
                 command_line TEXT,
                 start_time INTEGER,
                 elapsed_time TEXT,
                 total_hosts INTEGER,
                 total_open_ports INTEGER)''')

    c.execute('''CREATE TABLE IF NOT EXISTS hosts
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 scan_id INTEGER,
                 ip TEXT,
                 hostname TEXT,
                 os TEXT,
                 ports_tested INTEGER,
                 ports_open INTEGER,
                 ports_closed INTEGER,
                 ports_filtered INTEGER,
                 start_time INTEGER,
                 end_time INTEGER,
                 FOREIGN KEY (scan_id) REFERENCES scans (id))''')

    c.execute('''CREATE TABLE IF NOT EXISTS ports
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 scan_id INTEGER,
                 host_id INTEGER,
                 port TEXT,
                 protocol TEXT,
                 state TEXT,
                 service_name TEXT,
                 service_info TEXT,
                 http_title TEXT,
                 ssl_common_name TEXT,
                 ssl_issuer TEXT,
                 FOREIGN KEY (scan_id) REFERENCES scans (id),
                 FOREIGN KEY (host_id) REFERENCES hosts (id))''')

    conn.commit()
    return conn


def insert_data(conn, scan, hosts):
    """
    Inserts parsed Nmap scan data into the SQLite database. This includes scan metadata,
    details of the hosts identified, and information about open ports for each host.

    Args:
        conn (sqlite3.Connection): Connection object to the SQLite database.
        scan (dict): A dictionary containing metadata about the Nmap scan (version, command line, etc.).
        hosts (list): A list of dictionaries, each representing a host discovered in the scan.
                      Each host contains information about open ports and other attributes.
    """
    c = conn.cursor()

    c.execute("INSERT INTO scans (nmap_version, command_line, start_time, elapsed_time, total_hosts, total_open_ports) VALUES (?, ?, ?, ?, ?, ?)",
              (scan['nmap_version'], scan['command_line'], scan['start_time'], scan['elapsed_time'], scan['total_hosts'], scan['total_open_ports']))
    scan_id = c.lastrowid

    for host in hosts:
        c.execute("INSERT INTO hosts (scan_id, ip, hostname, os, ports_tested, ports_open, ports_closed, ports_filtered, start_time, end_time) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                  (scan_id, host['ip'], host['hostname'], host['os'], host['ports_tested'], host['ports_open'], host['ports_closed'], host['ports_filtered'], host['start_time'], host['end_time']))
        host_id = c.lastrowid

        for port in host['ports']:
            c.execute("INSERT INTO ports (scan_id, host_id, port, protocol, state, service_name, service_info, http_title, ssl_common_name, ssl_issuer) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                      (scan_id, host_id, port['port'], port['protocol'], port['state'], port['service_name'], port['service_info'], port['http_title'], port['ssl_common_name'], port['ssl_issuer']))

    conn.commit()


def main():
    parser = argparse.ArgumentParser(description="Process nmap scan results.")
    parser.add_argument("--xml_file", default="./nmap-data/nmap_output.xml", help="Path to the nmap output XML file")
    parser.add_argument("--db_path", default="./nmap-data/nmap_results.db", help="Path to the SQLite database file")
    args = parser.parse_args()

    xml_file = args.xml_file
    db_path = args.db_path
    if not os.path.exists(xml_file):
        print(f"Error: XML file not found at {xml_file}")
        print("Please provide a valid path to the XML file using the --xml_file argument.")
        return

    try:
        scan, hosts = parse_nmap_xml(xml_file)
        conn = create_database(db_path)
        insert_data(conn, scan, hosts)
        conn.close()
        print(f"Data successfully inserted into the database: {db_path}")
    except ParseError:
        print(f"Error: Unable to parse the XML file at {xml_file}")
        print("Please ensure it's a valid Nmap XML output file.")
    except sqlite3.Error as e:
        print(f"Database error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


if __name__ == '__main__':
    main()
