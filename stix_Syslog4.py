#!/usr/bin/python3

import sys
import socket
import json
import re
import io
import urllib.request as urllib2
import datetime
import time
import pytz
import logging
import pprint
from urllib.parse import urlparse
import argparse
from stix.core import STIXPackage
from stix.utils.parser import EntityParser
import libtaxii as t
import libtaxii.messages_11 as tm11
import libtaxii.clients as tc

# Configure logging
logging.basicConfig(level=logging.INFO)

# Set Global Timeout
socket.setdefaulttimeout(30)

# Default Config
CONFIG = {
    'FACILITY': {
        'kern': 0, 'user': 1, 'mail': 2, 'daemon': 3, 'auth': 4, 'syslog': 5, 
        'lpr': 6, 'news': 7, 'uucp': 8, 'cron': 9, 'authpriv': 10, 'ftp': 11, 
        'local0': 16, 'local1': 17, 'local2': 18, 'local3': 19, 'local4': 20, 
        'local5': 21, 'local6': 22, 'local7': 23
    },
    'LEVEL': {
        'emerg': 0, 'alert': 1, 'crit': 2, 'err': 3, 'warning': 4, 'notice': 5,
        'info': 6, 'debug': 7
    },
    'DESTINATION_IP': {
        'ip': '10.10.10.10',
        'port': '514'
    }
}

EMAIL_REGEX = r"[^@]+@[^@]+\.[^@]+"
IP_REGEX = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
DOMAIN_REGEX = r"^:"

def syslog(message, level=CONFIG['LEVEL']['notice'], facility=CONFIG['FACILITY']['daemon'], host='localhost', port=1514):
    """Sends a message to the syslog server using UDP."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        data = '<%d>%s' % (level + facility * 8, message)
        sock.sendto(data.encode('utf-8'), (host, port))
    except socket.error as e:
        logging.error(f"Socket error: {e}")
    finally:
        sock.close()

def extract_observable(args, obs, values):
    """Extract observable from a STIX observation."""
    typ = obs["properties"]["xsi:type"]
    if args.type and args.type != typ:
        return
    val = None
    if typ == "AddressObjectType":
        val = obs["properties"]["address_value"]["value"] if 'value' in obs["properties"]["address_value"] else obs["properties"]["address_value"]
    elif typ in ["URIObjectType", "DomainNameObjectType", "HostnameObjectType"]:
        val = obs["properties"]["value"]["value"] if 'value' in obs["properties"]["value"] else obs["properties"]["value"]
    elif typ == "UserAccountObjectType":
        val = obs["properties"]["username"]
    elif typ == "FileObjectType":
        val = [hashval["simple_hash_value"]["value"] if 'simple_hash_value' in hashval else hashval for hashval in obs["properties"]["hashes"]]
    if val:
        if not isinstance(val, str) and isinstance(val, collections.Iterable):
            values.extend(val)
        else:
            values.append(val)
    elif args.strict:
        raise Exception(f"Encountered unsupported CybOX observable type: {typ}")
    else:
        logging.warning(f"Encountered unsupported CybOX observable type: {typ}, ignoring...")

def extract_observables(args, indicators):
    """Extract observables from STIX indicators."""
    values = []
    for indicator in indicators:
        obs = indicator["observable"] if "observable" in indicator else indicator
        try:
            if 'object' in obs:
                extract_observable(args, obs["object"], values)
            elif 'observable_composition' in obs:
                for observable in obs["observable_composition"]["observables"]:
                    if 'object' in observable:
                        extract_observable(args, observable["object"], values)
            else:
                raise Exception("Unknown Object Type!! Please Investigate")
        except Exception as e:
            logging.error("Could not handle observable/indicator:")
            pprint.pprint(indicator, stream=sys.stderr)
            raise e
    return values

def process_package_dict(args, stix_dict):
    """Process STIX package dictionary and extract indicators and observables."""
    values = []
    dest = CONFIG['DESTINATION_IP']['ip']
    dest_port = int(CONFIG['DESTINATION_IP']['port'])
    if "observables" in stix_dict:
        values.extend(extract_observables(args, stix_dict["observables"]["observables"]))
    if "indicators" in stix_dict:
        values.extend(extract_observables(args, stix_dict["indicators"]))

    if len(values) > 0:
        for item in values:
            try:
                if re.match("^(http|https)", item):
                    handle_website(item, args, dest, dest_port)
                elif re.match(EMAIL_REGEX, item):
                    handle_email(item, args, dest, dest_port)
                elif re.match(IP_REGEX, item):
                    handle_ip(item, args, dest, dest_port)
                elif re.match(DOMAIN_REGEX, item):
                    handle_domain(item[2:], args, dest, dest_port)
                elif re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}$", item):
                    handle_ip_port(item, args, dest, dest_port)
                else:
                    handle_indicator(item, args, dest, dest_port)
            except ValueError as e:
                logging.error(f"Could not parse values: {item}")
                raise e
    return len(values)

def handle_website(item, args, dest, dest_port):
    """Handle website indicators."""
    u = urlparse(item)
    if args.verbose:
        logging.info(f'Web Site: {u.netloc} | Path: {u.path}')
    if args.outfile:
        with open('WebSites.txt', 'a') as mysites:
            mysites.write(f"{item}\n")
    if args.arcsight:
        cef = f'CEF:0|CE-OSINT|CE-ISAC|1.0|100|Known Malicious Website|1|request={item} shost={u.netloc} msg=CE-OSINT Malicious Domain {u.netloc}'
        time.sleep(0.02)
        syslog(cef, host=dest, port=dest_port)

def handle_email(item, args, dest, dest_port):
    """Handle email indicators."""
    if args.verbose:
        logging.info(f'Email Address: {item}')
    if args.outfile:
        with open('EmailAddresses.txt', 'a') as myemails:
            myemails.write(f"{item}\n")
    if args.arcsight:
        cef = f'CEF:0|CE-OSINT|CE-ISAC|1.0|100|Known Malicious Email|1|suser={item} msg=CE-OSINT Malicious Email {item}'
        time.sleep(0.02)
        syslog(cef, host=dest, port=dest_port)

def handle_ip(item, args, dest, dest_port):
    """Handle IP indicators."""
    if args.verbose:
        logging.info(f'IP Address: {item}')
    if args.outfile:
        with open('MyIPs.txt', 'a') as myips:
            myips.write(f"{item}\n")
    if args.arcsight:
        cef = f'CEF:0|CE-OSINT|CE-ISAC|1.0|100|Known Malicious Host|1|src={item} msg=CE-OSINT Malicious IP {item}'
        time.sleep(0.2)
        syslog(cef, host=dest, port=dest_port)

def handle_domain(item, args, dest, dest_port):
    """Handle domain indicators."""
    if args.verbose:
        myitem = 'http://' + item
        d = urlparse(myitem)
        item = d.netloc
        logging.info(f'Domain: {d.netloc}')
    if args.outfile:
        with open('AdditionalDomains.txt', 'a') as adom:
            adom.write(f"{item}\n")
    if args.arcsight:
        cef = f'CEF:0|CE-OSINT|CE-ISAC|1.0|100|Malicious Domain|1|request={item} msg=CE-OSINT Malicious Domain {d.netloc}'
        time.sleep(0.2)
        syslog(cef, host=dest, port=dest_port)

def handle_ip_port(item, args, dest, dest_port):
    """Handle IP and port indicators."""
    data = item.split(":")
    if args.verbose:
        logging.info(f'IP Address: {data[0]} | Dest Port: {data[1]}')
    if args.outfile:
        with open('IPandPort.txt', 'a') as IPdom:
            IPdom.write(f"{item}\n")
    if args.arcsight:
        cef = f'CEF:0|CE-OSINT|CE-ISAC|1.0|100|Known Malicious IP and Port|1|src={data[0]} dpt={data[1]} msg=NH-ISAC Malicious IP {data[0]} and Port {data[1]}'
        time.sleep(0.2)
        syslog(cef, host=dest, port=dest_port)

def handle_indicator(item, args, dest, dest_port):
    """Handle general indicators."""
    if args.verbose:
        logging.info(f'Indicator: {item}')
    if args.outfile:
        with open('Indicators.txt', 'a') as Idom:
            Idom.write(f"{item}\n")
    if args.arcsight:
        cef = f'CEF:0|CE-OSINT|CE-ISAC|1.0|100|Known Malicious Indicator|1|cs1={item} msg=CE-OSINT Malicious Indicator {item}'
        time.sleep(0.2)
        syslog(cef, host=dest, port=dest_port)

def get_parser():
    """Get the argument parser."""
    parser = argparse.ArgumentParser(description="A utility that imports STIX documents from either a TAXII server collection or a file.")
    parser.add_argument('-f', '--file', help='STIX file to import. Either this parameter or a STIX file is required', type=str)
    parser.add_argument('-o', '--outfile', help='Output the data to a text file', action='store_true')
    parser.add_argument('-y', '--type', help='Only import this type of indicator', type=str)
    parser.add_argument('--strict', action='store_true', help='Raise an error on an unsupported indicator. Defaults to simply printing to stderr.')
    parser.add_argument('--verbose', action='store_true', help='Print various inputs and outputs to STDERR')
    parser.add_argument('-a', '--sysserver', help='Send the data to syslog server using CEF Syslog', action='store_true')
    parser.add_argument('-x', '--taxii', help='TAXII Server Endpoint. Either this parameter or a STIX file is required.', type=str)
    parser.add_argument('-p', '--taxiiport', default="80", help='Port for the TAXII Server', type=str)
    parser.add_argument('-c', "--collection", default="default", help="TAXII Data Collection to poll. Defaults to 'default'.")
    parser.add_argument('--taxii_endpoint', help="TAXII Service Endpoint. Required if --taxii is provided.", type=str)
    parser.add_argument('--taxii_ssl', action='store_true', help='Use SSL for the TAXII request')
    parser.add_argument('--taxii_username', help='Username for TAXII BASIC authentication, if any', type=str)
    parser.add_argument('--taxii_password', help='Password for TAXII BASIC authentication, if any', type=str)
    parser.add_argument('--taxii_start_time', dest='begin_ts', help="The start timestamp (YYYY-MM-dd HH:MM:SS) in UTC for the taxii poll request. Defaults to None.", type=str)
    parser.add_argument('--taxii_end_time', dest='end_ts', help="The end timestamp (YYYY-MM-dd HH:MM:SS) in UTC for the taxii poll request. Defaults to None.", type=str)
    return parser

def main():
    """Main function to process command line arguments and initiate actions."""
    parser = get_parser()
    args = parser.parse_args()

    if args.help:
        parser.print_help()
        return

    if args.taxii:
        handle_taxii_request(args)
    elif args.file:
        stix_package = STIXPackage.from_xml(args.file)
        indicators = process_package_dict(args, stix_package.to_dict())
        logging.info(f"Imported {indicators} indicators into set")
    else:
        logging.error("Invalid arguments. Type 'python stix_Arcsight.py --help' for usage.")

def handle_taxii_request(args):
    """Handle TAXII server request."""
    try:
        begin_ts = datetime.datetime.strptime(args.begin_ts, '%Y-%m-%d %H:%M:%S').replace(tzinfo=pytz.UTC) if args.begin_ts else None
        end_ts = datetime.datetime.strptime(args.end_ts, '%Y-%m-%d %H:%M:%S').replace(tzinfo=pytz.UTC) if args.end_ts else None
    except ValueError:
        logging.error("Could not parse either start or end time")
        raise

    poll_req = tm11.PollRequest(
        message_id=tm11.generate_message_id(),
        collection_name=args.collection,
        exclusive_begin_timestamp_label=begin_ts,
        inclusive_end_timestamp_label=end_ts,
        poll_parameters=tm11.PollRequest.PollParameters()
    )
    poll_req_xml = poll_req.to_xml()
    client = tc.HttpClient()

    if args.taxii_ssl:
        client.setUseHttps(True)

    if args.taxii_username and not args.taxii_password:
        args.taxii_password = getpass.getpass("Enter your taxii password: ")

    client.setAuthCredentials({'username': args.taxii_username, 'password': args.taxii_password})
    resp = client.callTaxiiService2(args.taxii, f'{args.taxii_endpoint}/poll/', t.VID_TAXII_XML_11, poll_req_xml, args.taxiiport)
    response_message = t.get_message_from_http_response(resp, '0')

    response_dict = response_message.to_dict()
    indicators = 0
    if 'content_blocks' in response_dict:
        for content in response_dict["content_blocks"]:
            binding_id = content["content_binding"]["binding_id"]
            if binding_id and binding_id.startswith("urn:stix.mitre.org:xml"):
                try:
                    stix_pkg = STIXPackage.from_xml(io.BytesIO(content["content"]))
                    indicators += process_package_dict(args, stix_pkg.to_dict())
                except ValueError:
                    logging.error("Could not parse STIX document:")
                    logging.error(content["content"])
                    raise
        logging.info(f"Imported {indicators} indicators into set")
    else:
        logging.error("Invalid response from TAXII server")
        pprint.pprint(response_dict, stream=sys.stderr)
        exit(255)

if __name__ == "__main__":
    main()
