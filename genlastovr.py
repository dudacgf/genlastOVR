#!/usr/bin/env python3

import argparse
import tempfile
import subprocess
import os
import datetime
import calendar

from io import BytesIO 
from xml.dom import minidom
import yaml
import pycurl
import json

from gvm.connections import UnixSocketConnection, TLSConnection, SSHConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeCheckCommandTransform
from gvm.xml import pretty_print
from gvm.protocols.gmp._gmp226 import ReportFormatType

weekdir = ''
reportdir = ''
config = []

def initializations():
    global config, weekdir, reportdir

    print('Performing initializations')
    #
    # check and parse args 
    PROG_DESCRIPTION="Gen Last OVRs - runs openvasreporting over the last report of one or more tasks"
    CONFIG_FILE_HELP="path to a .yml file containing options defining the tasks and report formats\n"

    parser = argparse.ArgumentParser(
        prog="genlastovr",  # TODO figure out why I need this in my code for -h to show correct name
        description=PROG_DESCRIPTION,
        allow_abbrev=True,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("-c", "--config-file", dest="config_file",help=CONFIG_FILE_HELP,
                        required=False, default='genlastovr.yml')
    args = parser.parse_args()
    #
    # read and parse yaml config file
    with open(args.config_file, 'r') as c:
        config = yaml.safe_load(c)
    #
    # create this week work and report dirs
    today = datetime.date.today()
    year = today.year
    month = today.month
    week = today.day // 7 + 1
    weekdir = f'{config["workdir"]}/{year}-{month}/w{week}'
    reportdir = f'{weekdir}/reports'
    os.makedirs(reportdir, exist_ok=True)


def get_last_reports():
    """
    export last report for each task named in the config file
    """

    print('Exporting tasks\' last reports')
    #
    # generate the xml reports for all tasks in config
    gvm = config['gvm']
    if gvm['connection'] == 'sock':
        connection = UnixSocketConnection(path=gvm['sock_path'])
    elif gvm['connection'] == 'tls':
        connection = TLSConnection(hostname=gvm['hostname'], port=gvm['port'])
    elif gvm['connection'] == 'ssh':
        connection = SSHConnection(hostname=gvm['hostname'], port=gvm['port'], 
                                   username=gvm['username'], password=gvm['password'],
                                   known_hosts_file="/home/duda/vuln-scan/bin/khosts", auto_accept_host=True) 
    transform = EtreeCheckCommandTransform()
    with Gmp(connection=connection, transform=transform) as gmp:
        gmp.authenticate(config['credentials']['user'], config['credentials']['password'])

        # Retrieve all tasks
        tasks = gmp.get_tasks()

        # retrieve last_report for every task in config['tasks'] and write it to xml file
        for t in tasks.iter('task'):
            task_name = t.xpath('name/text()')[0]
            if task_name in config['tasks']:
                report_id = t.xpath('last_report/report')[0].attrib['id']
                report = gmp.get_report(report_id, 
                             report_format_id=ReportFormatType.XML, 
                             filter_string=f'{config["global_filter"]}')
                only_report = report.xpath('report')[0]
                with open(f'{reportdir}/{task_name}-report.xml', 'w') as r:
                    pretty_print(only_report, r)
                print(f'Exported task [{task_name}] last xml report run at [{only_report.xpath("name/text()")[0]}]')


def _cvenum(e):
    # this function will be used for cve list sort
    try:
       [dummy, year, number] = e.split('-')
    except:
       pass
    try:
       [dummy, year, number, dummy] = e.split('-')
    except:
       return(0);
    padded_number = "%010d" % int(number)
    return(int(f'{year}{padded_number}'))


def get_last_cisa():
    """
    generates a file with the list of cisa known active exploits
    """

    print('Generating list of CISA known active exploit\'s CVEs')
    #
    # reads cisa's list and writes only the cve numbers to a text file
    b_obj = BytesIO() 
    crl = pycurl.Curl() 
    crl.setopt(crl.URL, config['cisa_url'])
    crl.setopt(crl.WRITEDATA, b_obj)
    crl.perform() 
    crl.close()
    # read content returned as json
    cisa = json.loads(b_obj.getvalue().decode('utf8'))
    cves = []
    for vuln in cisa['vulnerabilities']:
       cves.append(vuln['cveID'])
    cves.sort(reverse=False, key=_cvenum)
    with open(f'{config["workdir"]}{config["cisa_file"]}', 'w') as c:
        c.write('\n'.join(cve for cve in cves))


def get_last_ms_patches():
    """
    get last Microsoft's list of second tuesday patches
    """
    def second_tuesday():
        c = calendar.Calendar()
        today = datetime.date.today()
        month = today.month
        year = today.year
        return list(filter(lambda d:d[3] == 1 and d[1] == month,  
                           c.itermonthdays4(year, month)))[1][2]

    # check if beyond second tuesday of this month
    print('Generating list of Microsoft\'s most recent monthly updates')
    today = datetime.date.today()
    if second_tuesday() < today.day: 
        # yep, get this month's list of patches
        year = today.year
        mname = today.strftime("%b")
    else: 
        # nope, get last month's list of patches
        ldp_month = datetime.date.today().replace(day=1) - datetime.timedelta(days=1)
        year = ldp_month.year
        mname = ldp_month.strftime("%b")
    url=f'{config["ms_url"]}{year}-{mname}'
    #
    # reads ms patches list and writes only the cve numbers to a text file
    b_obj = BytesIO() 
    crl = pycurl.Curl() 
    crl.setopt(crl.URL, url)
    crl.setopt(crl.WRITEDATA, b_obj)
    crl.perform() 
    crl.close()
    # read content returned by curl as xml
    xmldoc = minidom.parseString(b_obj.getvalue().decode('utf8'))
    list_cves = xmldoc.getElementsByTagName('vuln:CVE')
    cves = []
    for item in list_cves:
        cves.append(item.firstChild.wholeText)
    cves.sort(reverse=False, key=_cvenum)
    with open(f'{config["workdir"]}{config["ms_file"]}', 'w') as c:
        c.write('\n'.join(cve for cve in cves))


def gen_reports():
    """
    generate all OVR reports.
    """
    def filter_file(contents: list):
        f = tempfile.NamedTemporaryFile(mode='w', encoding='utf8', dir='/tmp', delete=False)
        f.write('\n'.join(c for c in contents))
        f.close()
        return f

    print('Generating OVRs')
    for report in config['reports']:
        thisreport = config['reports'][report]
        filters = []

        cmdline = ['openvasreporting']
        for i in thisreport['input']: cmdline.extend(['-i', f'{reportdir}/{i}'])
        #
        # format of the report
        if not 'format' in thisreport:
            thisreport['format'] = 'xlsx' # this is the default
        cmdline.extend(['-f', thisreport['format']])
        #
        # exclude/include filters
        allFilters = [('network', 'n'), ('cve', 'e'), ('regex', 'r')]
        for afilter in allFilters:
            if afilter[0] in thisreport:
                # if excludes/includes are lists, save the list as lines in a temp file
                # if not, it is probably a relative path
                if 'includes' in thisreport[afilter[0]]:
                    if isinstance(thisreport[afilter[0]]['includes'], list):
                         f = filter_file(thisreport[afilter[0]]['includes'])
                         cmdline.extend([f'-{afilter[1]}', f.name])
                         filters.append(f)
                    else:
                         cmdline.extend([f'-{afilter[1]}', f'{config["workdir"]}/{thisreport[afilter[0]]["includes"]}'])
                if 'excludes' in thisreport[afilter[0]]:
                    if isinstance(thisreport[afilter[0]]['excludes'], list):
                        f = filter_file(thisreport[afilter[0]]['excludes'])
                        cmdline.extend([f'-{afilter[1].upper()}', f.name])
                        filters.append(f)
                    else:
                         cmdline.extend([f'-{afilter[1].upper()}', f'{config["workdir"]}/{thisreport[afilter[0]]["excludes"]}'])
        #
        # level of the cves to be filtered in the report
        if 'level' in thisreport:
            cmdline.extend(['-l', thisreport['level']])
        #
        # reporttype
        if not 'reporttype' in thisreport:
            thisreport['reporttype'] = ['v']
        #
        # generates an OVR for each reporttype
        for rtype in thisreport['reporttype']:
            c = cmdline.copy()
            c.extend(['-T', rtype])
            c.extend(['-o', f'{weekdir}/{report}_by{rtype.upper()}.{thisreport["format"]}'])
            #print(f'command: {c}')
            cp = subprocess.run(c, capture_output=True)
            if cp.returncode == 0:
                print(f'OVR {weekdir}/{report}_by{rtype.upper()}.{thisreport["format"]} created.')
            else:
                erro = cp.stderr[:-1].decode("unicode_escape").split('\n')[-1] # discard traceback
                print(f'Error generating OVR {weekdir}/{report}_by{rtype.upper()}.{thisreport["format"]}: {erro}')
        #
        # clean up temporary filter files
        for f in filters: os.unlink(f.name)


def main():
    initializations()
    # grab data
    get_last_cisa()
    get_last_ms_patches()
    get_last_reports()
    # generate the reports
    gen_reports()


if __name__ == "__main__":
    main()

