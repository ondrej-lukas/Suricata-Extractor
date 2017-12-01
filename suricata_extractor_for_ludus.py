#!/usr/bin/python -u
# See the file 'LICENSE' for copying permission.
# Author: Sebastian Garcia. eldraco@gmail.com , sebastian.garcia@agents.fel.cvut.cz

import sys
from datetime import datetime
from datetime import timedelta
import argparse
import time
from os.path import isfile, join
import json
from pprint import pprint
#import matplotlib.pyplot as plt
#import matplotlib.patches as mpatches
import math
from multiprocessing import Queue
import multiprocessing
from itertools import islice
version = '0.3.2'


# Changelog
# 0.3.1
#  Output information for each combination of ports accessed by each uniq attacker
# 0.3.1:
#  Delete the export in csv
#  Only suricata categories with data is exported in the json
#  Export in json
#  Add summary of alerts per dst port
# 0.3: 
#  Fix the Unknown category in the csv
# 0.2: 
#  Generate the csv
#  Plot the data
#  Generate an image file

timewindows = {}
timeStampFormat = '%Y-%m-%dT%H:%M:%S.%f'
categories = {'Not Suspicious Traffic':[], 'Unknown Traffic':[], 'Potentially Bad Traffic':[], 'Attempted Information Leak':[], 'Information Leak':[], 'Large Scale Information Leak':[], 'Attempted Denial of Service':[], 'Denial of Service':[], 'Attempted User Privilege Gain':[], 'Unsuccessful User Privilege Gain':[], 'Successful User Privilege Gain':[], 'Attempted Administrator Privilege Gain':[], 'Successful Administrator Privilege Gain':[], 'Decode of an RPC Query':[], 'Executable Code was Detected':[], 'A Suspicious String was Detected':[], 'A Suspicious Filename was Detected':[], 'An Attempted Login Using a Suspicious Username was Detected':[], 'A System Call was Detected':[], 'A TCP Connection was Detected':[], 'A Network Trojan was Detected':[], 'A Client was Using an Unusual Port':[], 'Detection of a Network Scan':[], 'Detection of a Denial of Service Attack':[], 'Detection of a Non-Standard Protocol or Event':[], 'Generic Protocol Command Decode':[], 'Access to a Potentially Vulnerable Web Application':[], 'Web Application Attack':[], 'Misc activity':[], 'Misc Attack':[], 'Generic ICMP event':[], 'Inappropriate Content was Detected':[], 'Potential Corporate Privacy Violation':[], 'Attempt to Login By a Default Username and Password':[]}
colors = ['#d6d6f5','#7070db','#24248f','#ffccff','#ff1aff','#990099','#ffb3d1','#ff0066','#99003d','#ffe6b3','#ffcc66','#ffaa00','#ffffb3','#ffff00','#cccc00','#d9ffb3','#99ff33','#66cc00','#c6ecd9','#66cc99','#2d8659','#c2f0f0','#47d1d1','#248f8f','#b3f0ff','#00ccff','#008fb3','#b3ccff','#6699ff','#004de6','#ffccff','#ff66ff','#b300b3','#ffb3d1']


###################
# TimeWindow
class TimeWindow(object):
    """ Store info about the time window """
    def __init__(self, tw_start,tw_end):
        self.start = tw_start
        self.end = tw_end

        self.categories = {}
        self.severities = {}
        self.severities[1] = 0
        self.severities[2] = 0
        self.severities[3] = 0
        self.severities[4] = 0

        self.signatures = {}
        self.src_ips = {}
        self.dst_ips = {}
        self.src_ports = {}
        self.dst_ports = {}
        # port_combinations will be: {dstip: {srcip: [1st port, 2nd port]}}
        self.port_combinations = {}
        self.final_count_per_dst_ip = {}
        # bandwidth = {dstport: [mbits]}
        self.bandwidth = {}

    def add_flow(self, src_ip, dst_ip, srcport, dstport, proto, bytes_toserver, bytes_toclient):
        """
        Receive a flow and use it
        """
        if 'TCP' in proto:
            try:
                data = self.bandwidth[dstport]
                self.bandwidth[dstport] += bytes_toserver + bytes_toclient
            except KeyError:
                self.bandwidth[dstport] = bytes_toserver + bytes_toclient

    def add_alert(self, category, severity, signature, src_ip, dst_ip, srcport, destport):
        """
        Receive an alert and it adds it to the TW
        TODO:Check if there are any new fields in eve.json
        """
        # Categories
        if category == '':
            try:
                self.categories['Unknown Traffic'] += 1
            except KeyError:
                self.categories['Unknown Traffic'] = 1
        else:
            try:
                self.categories[category] += 1
            except KeyError:
                self.categories[category] = 1
        # Severities
        try:
            self.severities[int(severity)] += 1
        except KeyError:
            self.severities[int(severity)] = 1
        # Signatures
        try:
            self.signatures[signature] += 1
        except KeyError:
            self.signatures[signature] = 1
        # Srcip
        try:
            self.src_ips[src_ip] += 1
        except KeyError:
            self.src_ips[src_ip] = 1
        # Dstip
        try:
            self.dst_ips[dst_ip] += 1
        except KeyError:
            self.dst_ips[dst_ip] = 1
        # Srcport
        try:
            self.src_ports[srcport] += 1
        except KeyError:
            self.src_ports[srcport] = 1
        # dstport
        try:
            self.dst_ports[destport] += 1
        except KeyError:
            self.dst_ports[destport] = 1

        #port combination
        if destport != '':
            try:
                srcdict = self.port_combinations[dst_ip]
                try:
                    # the dstip is there, the srcip is also there, just add the port
                    ports = srcdict[src_ip]
                    # We have this dstip, srcip, just add the port
                    try:
                        ports.index(destport)
                    except ValueError:
                        ports.append(destport)
                    srcdict[src_ip] = ports
                    self.port_combinations[dst_ip] = srcdict
                    #print 'Added port {}, to srcip {} attacking dstip {}'.format(destport, src_ip, dst_ip)
                except KeyError:
                    # first time for this src_ip attacking this dst_ip
                    ports = []
                    ports.append(destport)
                    srcdict[src_ip] = ports
                    self.port_combinations[dst_ip] = srcdict
                    #print 'New srcip {} attacking dstip {} on port {}'.format(src_ip, dst_ip, destport)
            except KeyError:
                # First time for this dst ip
                ports = []
                ports.append(destport)
                srcdict = {}
                srcdict[src_ip] = ports
                self.port_combinations[dst_ip] = srcdict
                #print 'New dst IP {}, attacked from srcip {} on port {}'.format(dst_ip, src_ip, destport)

    def get_json(self):
        """
        Returns the json representation of the data in this time window
        """
        data = {}
        data['Alerts Categories'] = self.categories
        data['# Uniq Signatures'] = len(self.signatures)
        data['# Severity 1'] = self.severities[self.severities.keys()[0]]
        data['# Severity 2'] = self.severities[self.severities.keys()[1]]
        data['# Severity 3'] = self.severities[self.severities.keys()[2]]
        data['# Severity 4'] = self.severities[self.severities.keys()[3]]
        data['Alerts/DstPort'] = self.dst_ports
        #data['Alerts/SrcPort'] = self.src_ports
        data['Alerts/SrcIP'] = self.src_ips
        data['Alers/DstIP'] = self.dst_ips
        data['Per SrcPort'] = self.src_ports
        #data['port_combinations'] = self.get_port_combination_lines
        json_result = json.dumps(data)
        return json_result

    def count_port_combinations(self):
        """
        Compute the amount of attackers attacking each port combination on each dst ip
        """
        self.final_count_per_dst_ip = {}
        final_ports_counts = {}
        for dst_ip in self.port_combinations:
            for src_ip in self.port_combinations[dst_ip]:
                # We count precisely who attacks ports 22,80, ... no 22,80,443 as also 22,80
                portscom = str(self.port_combinations[dst_ip][src_ip]).replace('[','').replace(']','')
                try:
                    amount = final_ports_counts[portscom]
                    amount += 1
                    final_ports_counts[portscom] = amount
                except KeyError:
                    amount = 1
                    final_ports_counts[portscom] = amount
            self.final_count_per_dst_ip[dst_ip] = final_ports_counts
            final_ports_counts = {}
    
    def get_port_combination_lines(self):
        """
        Call the combination of ports and return an object with all the info for this TW.
        """
        self.count_port_combinations()
        return self.final_count_per_dst_ip

    def __repr__(self):
        return 'TW: {}. #Categories: {}. #Signatures: {}. #SrcIp: {}. #DstIP: {}. #Severities: 1:{}, 2:{}, 3:{}, 4:{}'.format(str(self.start), len(self.categories), len(self.signatures), len(self.src_ips), len(self.dst_ips), self.severities[self.severities.keys()[0]], self.severities[self.severities.keys()[1]], self.severities[self.severities.keys()[2]], self.severities[self.severities.keys()[3]])

    def printit(self):
        print 'TW: {}. #Categories: {}. #Signatures: {}. #SrcIp: {}. #DstIP: {}. #Severities: 1:{}, 2:{}, 3:{}, 4:{}'.format(str(self.start), len(self.categories), len(self.signatures), len(self.src_ips), len(self.dst_ips), self.severities[self.severities.keys()[0]], self.severities[self.severities.keys()[1]], self.severities[self.severities.keys()[2]], self.severities[self.severities.keys()[3]])


def roundTime(dt=None, date_delta=timedelta(minutes=1), to='average'):
    """
    Round a datetime object to a multiple of a timedelta
    dt : datetime.datetime object, default now.
    dateDelta : timedelta object, we round to a multiple of this, default 1 minute.
    from:  http://stackoverflow.com/questions/3463930/how-to-round-the-minute-of-a-datetime-object-python
    """
    round_to = date_delta.total_seconds()
    if dt is None:
        dt = datetime.now()
    seconds = (dt - dt.min).seconds
    if to == 'up':
        # // is a floor division, not a comment on following line (like in javascript):
        rounding = (seconds + round_to) // round_to * round_to
    elif to == 'down':
        rounding = seconds // round_to * round_to
    else:
        rounding = (seconds + round_to / 2) // round_to * round_to
    return dt + timedelta(0, rounding - seconds, -dt.microsecond)

def summarize_ports():
    """
    After all the tw finished, summarize the port combinations in all the TW and print it in a separate file
    """
    port_summary = {}
    for tw in timewindows:
        ports_data = timewindows[tw].final_count_per_dst_ip
        for srcip in ports_data:
            try:
                #print 'Src IP: {}'.format(srcip)
                # ports for this ip alredy in the global dict
                srcip_ports = port_summary[srcip]
                #print 'Ports com we already have: {}'.format(srcip_ports)
                #print 'Ports com in the current tw: {}'.format(ports_data[srcip])
                # for each port in the ports for the src ip in the current tw
                for twport in ports_data[srcip]:
                    try:
                        # is this combination of ports in the global dict?
                        amount = srcip_ports[twport]
                        # yes, so add the new ports
                        srcip_ports[twport] += ports_data[srcip][twport]
                        #print 'We do have this comb. Updating to {}'.format(srcip_ports)
                    except KeyError:
                        # The new port combination is not in the global dict yet, just store the ports we have in the current tw
                        srcip_ports[twport] = ports_data[srcip][twport]
                        #print 'We do not have this comb. Updating to {}'.format(srcip_ports)
                # update the global dict for this src ip
                port_summary[srcip] = srcip_ports
            except KeyError:
                port_summary[srcip] = ports_data[srcip]
    summaryportsfilename = '.'.join(args.json.split('.')[:-1]) + '.summary_ports'
    summary_port_file = open(summaryportsfilename, 'w')
    for srcip in port_summary:
        summary_port_file.write(str(srcip) + ': ' + str(port_summary[srcip]) + '\n')
    summary_port_file.close()



class Extractor(object):
    """TODO: Documentation"""

    def __init__(self, filename=None):
        self.tw_archive = {}
        self.timewindow = None
        self.line_number =0
        """if filename:
            self.source = open(filename)
            self.from_file = True
        else:
            self.source = sys.stdin"""

    def process_line(self, line, timewindow):
        """
        Process each line, extract the columns, get the correct TW and store each alert on the TW object
        """
        json_line = json.loads(line)
        #check if we are in the timewindow
        line_timestamp = datetime.strptime(json_line['timestamp'].split('+')[0], timeStampFormat)
        if line_timestamp > timewindow.start and line_timestamp <= timewindow.end:
            if 'alert' not in json_line['event_type'] and 'flow' not in json_line['event_type']:
                return False
            """
            if args.dstnet and args.dstnet not in json_line['dest_ip']:
                return False
            """
            # forget the timezone for now with split
            try:
                col_time = json_line['timestamp'].split('+')[0]
            except KeyError:
                col_time = ''
            try:
                col_category = json_line['alert']['category']
            except KeyError:
                col_category = ''
            try:
                col_severity = json_line['alert']['severity']
            except KeyError:
                col_severity = ''
            try:
                col_signature = json_line['alert']['signature']
            except KeyError:
                col_signature = ''
            try:
                col_srcip = json_line['src_ip']
            except KeyError:
                col_srcip = ''
            try:
                col_dstip = json_line['dest_ip']
            except KeyError:
                col_dstip = ''
            try:
                col_srcport = json_line['src_port']
            except KeyError:
                col_srcport = ''
            try:
                col_dstport = json_line['dest_port']
            except KeyError:
                col_dstport = ''

            # Get the time window object
            if 'alert' in json_line['event_type']:
                timewindow.add_alert(col_category, col_severity, col_signature, col_srcip, col_dstip, col_srcport, col_dstport)
            elif 'flow' in json_line['event_type']:
                try:
                    col_proto = json_line['proto']
                except KeyError:
                    col_proto = ''
                try:
                    col_bytes_toserver = json_line['flow']['bytes_toserver']
                except KeyError:
                    col_bytes_toserver = ''
                try:
                    col_bytes_toclient = json_line['flow']['bytes_toclient']
                except KeyError:
                    col_bytes_toclient = ''
                timewindow.add_flow(col_srcip, col_dstip, col_srcport, col_dstport, col_proto, col_bytes_toserver, col_bytes_toclient)
                
    def get_data(self, tw_start, tw_end):
        self.timewindow = TimeWindow(tw_start,tw_end)
        """self.source = open("/root/var/log/suricata/eve.json")
        for line in self.source:
            print line
            self.process_line(line,self.timewindow)"""
        counter = 0;
        print "Starting at line:{}".format(self.line_number)
        with open("/root/var/log/suricata/eve.json") as lines:
            for line in islice(lines, self.line_number, None): #skip the lines we already inspected
                self.process_line(line,self.timewindow)
                counter+=1
        self.line_number += counter
        print "Number of processed lines:{}".format(counter)
        return self.timewindow.get_json()
    #there must be a better solution than to iterate

####################
# Main
####################
if __name__ == '__main__':  
    print 'Suricata Extractor. Version {} (https://stratosphereips.org)'.format(version)
    print

    """# Parse the parameters
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--verbose', help='Amount of verbosity. This shows more info about the results.', action='store', required=False, type=int, default=1)
    parser.add_argument('-e', '--debug', help='Amount of debugging. This shows inner information about the flows.', action='store', required=False, type=int, default=0)
    parser.add_argument('-f', '--file', help='Suricata eve.json file.', action='store', required=False)
    #parser.add_argument('-w', '--width', help='Width of the time window to process. In minutes.', action='store', required=False, type=int, default=60)
    #parser.add_argument('-d', '--dstnet', help='Destination net to monitor. Ex: 192.168 to search everything attacking 192.168.0.0/16 network', action='store', required=False)
    #parser.add_argument('-p', '--plot', help='Plot the data in an active window.', action='store_true', required=False)
    #parser.add_argument('-P', '--plotfile', help='Store the plot in this file. Extension can be .eps, .png or .pdf. I suggest eps for higher resolution', action='store', type=str, required=False)
    #parser.add_argument('-l', '--log', help='Plot in a logarithmic scale', action='store_true', required=False)
    #parser.add_argument('-j', '--json', help='Json file name to output data in the timewindow in json format. Much less columns outputed.', action='store', type=str, required=False)
    parser.add_argument('-o', '--ports', help='Compute information about the usage of ports by the attackers. For each combination of ports, count how many unique IPs connected to them. You need also to select JSON output. The results are stored in a file with the same name as the JSON file but with extension .ports', action='store_true', required=False)
    #parser.add_argument('-b', '--bandwidth', help='Compute the bandwidth consumption for the given set of ports. Ports numbers should be separated by comma. Only TCP ports supported. Bandwidth is computed in megabits per second on each timewindow, and then it is averaged at the end. The results per time window are included in the json file (so is mandatory to opt it) and the general final values are reported in a file with extension .bandwidth.', action='store_true', required=False)
    f = parser.parse_args()

    # Get the verbosity, if it was not specified as a parameter 
    if args.verbose < 1:
        args.verbose = 1

    # Limit any debuggisity to > 0
    if args.debug < 0:
        args.debug = 0

    # Json
    if args.json:
        jsonfile = open(args.json, 'w')

    if args.ports:
        portsfilename = '.'.join(args.json.split('.')[:-1]) + '.ports'
        portsfile = open(portsfilename, 'w')

    Extractor e = Extractor(queue, args.address, args.port)
    
    #current_tw = ''
    try:
        if args.file:
            if args.verbose > 1:
                print 'Working with the file {} as parameter'.format(args.file)
            f = open(args.file)
            line = f.readline()
            while line:
                queue.put(line)
                line = f.readline()
            f.close()
        else:
            while True:
                line = sys.stdin.readline()
                queue.put(line)
    except KeyboardInterrupt:
        # Do the final things
        print "\nLeaving Suricata Extractor"
        pass

    if args.json:
        jsonfile.close()

    ## Print last tw
    try:
        timestamp = datetime.strptime(current_tw.start_time, timeStampFormat)
        round_down_timestamp = roundTime(timestamp,timedelta(minutes=args.width), 'down')
        str_round_down_timestamp = round_down_timestamp.strftime(timeStampFormat)
        output_tw(str_round_down_timestamp)
    except AttributeError:
        print 'Not a final time window? Some error?'

    # Close files
    if args.json:
        jsonfile.close()


    if args.ports:
        # Here we do the final summary of ports in the complete file
        summarize_ports()
        portsfile.close()
"""
