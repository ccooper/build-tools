#!/usr/bin/env python

import os
import requests
import simplejson as json
from slaveapi.clients import ssh
import socket
import time

from furl import furl

import logging
from logging.handlers import RotatingFileHandler
log = logging.getLogger(__name__)
handler = RotatingFileHandler("restart_buckets.log",
                              maxBytes=52428800,
                              backupCount=10)
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
handler.setFormatter(formatter)
log.addHandler(handler)

from paramiko import SSHClient, AuthenticationException

buckets = {}
running_buckets = {}
SLEEP_INTERVAL = 60
ssh_key = "/Users/ccooper/.ssh/id_dsa"
username = "cltbld"

def IgnorePolicy():
    def missing_host_key(self, *args):
        pass

def put_masters_in_buckets(masters_json, master_list=None):
    for master in masters_json:
        if not master['enabled']:
            continue
        if master_list:
            if master['hostname'].split('.')[0] not in master_list:
                continue
        
        bucket_key = master['name'].split('-',1)[1]
        # We can parallelize restarts more in AWS because we're in different regions,
        # so make separate buckets for cloud pools.
        if "aws" in master['datacentre']:
            bucket_key += "-" + master['datacentre']
        if bucket_key not in buckets:
            buckets[bucket_key] = []
        buckets[bucket_key].append(master)
        # XXX: work with a single master for now
        return

def masters_remain():
    for key in running_buckets:
        if running_buckets[key]:
            return True
    for key in buckets:
        if buckets[key]:
            return True
    return False

class MasterConsole(ssh.SSHConsole):
    def connect(self, timeout=30):
        try:
            log.debug("Attempting to connect to %s as %s" % (self.fqdn, username))
            self.client.load_system_host_keys()
            self.client.connect(hostname=self.fqdn, username=username, key_filename=ssh_key, allow_agent=False)
            log.info("Connection as %s succeeded!", username)
            self.connected = True
        except AuthenticationException, e:
            log.debug("Authentication failure.")
            raise e
        except socket.error, e:
            # Exit out early if there is a socket error, such as:
            # ECONNREFUSED (Connection Refused). These errors are
            # typically raised at the OS level.
            from errno import errorcode
            log.debug("Socket Error (%s) - %s", errorcode[e[0]], e[1])
            raise e

def get_console(hostname):
    console = MasterConsole(hostname, None)
    try:
        console.connect()  # Make sure we can connect properly
        return console
    except (socket.error, ssh.SSHException), e:
        log.error(e)
        console.disconnect() # Don't hold a connection
        return None  # No valid console
    return None  # How did we get here?

def graceful_shutdown(master):
    # We do graceful shutdowns through the master's web interface
    log.info("Initiating graceful shutdown for %s" % master['hostname'])
    shutdown_url = furl("http://" + master['hostname'])
    shutdown_url.port = master['http_port']
    shutdown_url.path = "shutdown"
    try:
        # Disabling redirects is important here - otherwise we'll load a
        # potentially expensive page from the Buildbot master. The response
        # code is good enough to confirm whether or not initiating this worked
        # or not anyways.
        requests.post(str(shutdown_url), allow_redirects=False)
    except requests.RequestException:
        log.error("Failed to initiate graceful shutdown for %s" % master['hostname'])
        return False
    return True

def check_shutdown_status(master):
    # Returns true when there is no matching master process.
    # Example process:
    # /builds/buildbot/coop/tests-master/bin/python /builds/buildbot/coop/tests-master/bin/buildbot start /builds/buildbot/coop/tests-master/master
    log.info("Checking shutdown status of master: %s" % master['hostname'])
    cmd="ps auxww | grep python | grep start | grep %s" % master['master_dir']
    console = get_console(master['hostname'])
    rc, output = console.run_cmd(cmd)
    if rc != 0:
        log.info("No master process found on %s." % master['hostname'])
        return True
    log.info("Master process still exists on %s." % master['hostname'])
    return False
        
def restart_master(master):
    # Restarts buildbot on the remote master
    log.info("Attempting to restart master: %s" % master['hostname'])
    cmd = "cd %s; source bin/activate; make start" % master['basedir']
    console = get_console(master['hostname'])
    rc, output = console.run_cmd(cmd)
    if rc == 0:
        log.info("Master %s restarted successfully." % master['hostname'])
        return True
    log.warning("Restart of master %s failed, or never saw restart finish." % master['hostname'])
    return False

if __name__ == '__main__':
    import argparse
    import sys
    
    parser = argparse.ArgumentParser(description='Gracefully restart a list of buildbot masters')
    parser.add_argument("-v", "--verbose", dest="verbose", action="store_true",
                        help="Enable extra debug output")
    parser.add_argument("-m", "--masters-json", action="store", dest="masters_json", help="JSON file containing complete list of masters", required=True)
    parser.add_argument("-l", "--limit-to-masters", action="store", dest="limit_to_masters", help="Test file containing list of masters to restart, one per line", default=None)
    
    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")
    else:
        logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")        
        
    if not os.path.isfile(args.masters_json):
        log.error("Masters JSON file ('%s') does not exist. Exiting..." % args.masters_json)
        sys.exit(1)

    master_list = []
    if args.limit_to_masters:
        if not os.path.isfile(args.limit_to_masters):
            log.warning("Masters limit file ('%s') does not exist. Skipping..." % args.limit_to_masters)
        else:
            master_list = [line.strip() for line in open(args.limit_to_masters)]
            
    json_data = open(args.masters_json)
    masters_json = json.load(json_data)

    put_masters_in_buckets(masters_json, master_list)

    #import pprint
    #pp = pprint.PrettyPrinter(indent=4)
    #pp.pprint(buckets)
    #sys.exit(1)
    
    while masters_remain():
        # Refill our running buckets.
        # If we add a new master, we need to kick off the graceful shutdown too.
        for key in buckets:
            if key in running_buckets:
                continue
            else:
                if buckets[key]:
                    running_buckets[key] = buckets[key].pop()
                    #graceful_shutdown(running_buckets[key])

        #log.debug(running_buckets)
                    
        keys_processed = []
        for key in running_buckets:
            if check_shutdown_status(running_buckets[key]):
                if not restart_master(running_buckets[key]):
                    log.warning("Failed to restart master (%s). Please investigate by hand." % running_buckets[key]['hostname'])
                # Either way, we remove this master so we can proceed.
                keys_processed.append(key)
        for key in keys_processed:
            del running_buckets[key]
            
        if masters_remain():
            log.info("Sleeping for %ds" % SLEEP_INTERVAL)
            time.sleep(SLEEP_INTERVAL)
