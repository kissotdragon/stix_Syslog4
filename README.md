
# About stix_Syslog4
A STIX/TAXII client that grabs STIX data from a TAXII discovery service, parses out the indicators and observables, and can send the data via CEF Syslog to a Syslog endpoint

# Requirements
This script has been updated to run in Python3 --   

This script requires some python dependencies.  You can install these using pip3.

# Description
This script is a derivative of a script called stix_import.py created by IBM-Security

This is a script that connects to a TAXII server discovery service, grabs the STIX document, and parses out indicators and observables. Specifically looking for IP's, Websites, Email Addresses, and Hash's. It can output this to the console, a file, or create a CEF message which is then sent via syslog to a syslog endpoint. 

# Example Usage
## Import from TAXII Server
### Output to Console
    python3 stix_Syslog4.py --verbose -x 'soltra01' --taxii_endpoint '/taxii-discovery-service' -c system.Default --taxiiport=80 --taxii_username=soltraAnalyst1 --taxii_password='password' --taxii_start_time='2016-04-25 00:00:00' --taxii_end_time='2016-04-25 23:59:59'

### Save Data to a File
    python3 stix_Syslog4.py --outfile -x 'soltra01' --taxii_endpoint '/taxii-discovery-service' -c system.Default --taxiiport=80 --taxii_username=soltraAnalyst1 --taxii_password='password' --taxii_start_time='2016-04-25 00:00:00' --taxii_end_time='2016-04-25 23:59:59'

### Send Data to Syslog Server
    python3 stix_Syslog4.py --SysServer -x 'soltra01' --taxii_endpoint '/taxii-discovery-service' -c system.Default --taxiiport=80 --taxii_username=soltraAnalyst1 --taxii_password='password' --taxii_start_time='2016-04-25 00:00:00' --taxii_end_time='2016-04-25 23:59:59'

## Import from a STIX file
    python3 stix_Syslog4.py --verbose --file STIXDocument.xml 
    
## Display Help
    python3 stix_Syslog4.py [-h | --help]

Options:
  -h, --help            Show help message
  -f FILE, --file=FILE  STIX file to import. Either this parameter or a STIX
                        file is required
  -o, --outfile         Output the data to a text file
  -y TYPE, --type=TYPE  Only import this type of indicator
  --strict              Raise an error on an unsupported indicator. Defaults
                        to simply printing to stderr.
  --verbose             Print various inputs and outputs to STDERR
  -a, --sysserver        Send the data to syslog server using CEF format message
  -x TAXII, --taxii=TAXII
                        TAXII Server Endpoint. Either this parameter or a STIX
                        file is required.
  -p TAXIIPORT, --taxiiport=TAXIIPORT
                        Port for the TAXII Server
  -c COLLECTION, --collection=COLLECTION
                        TAXII Data Collection to poll. Defaults to 'default'.
  --taxii_endpoint=TAXII_ENDPOINT
                        TAXII Service Endpoint. Required if -x is provided.
  --taxii_ssl=TAXII_SSL
                        Set this to use SSL for the TAXII request
  --taxii_username=TAXII_USERNAME
                        Set this to the username for TAXII BASIC
                        authentication, if any
  --taxii_password=TAXII_PASSWORD
                        Set this to use password for TAXII BASIC
                        authentication, if any
  --taxii_start_time=BEGIN_TS
                        The start timestamp (YYYY-MM-dd HH:MM:SS) in UTC for
                        the taxii poll request. Defaults to None.
  --taxii_end_time=END_TS
                        The end timestamp (YYYY-MM-dd HH:MM:SS) in UTC for the
                        taxii poll request. Defaults to None.

Copyright 2025 Centeral Enterprises LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
