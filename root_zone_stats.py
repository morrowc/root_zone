#!/usr/bin/python
"""Parse a root hints file from:
 
http://www.internic.net/zones/root.zone
 
Provide some statstics about:
  o the number of unique zones
  o number of unique NS RR hostnames
  o number of unique netblocks in which the NS RR hostnames fall.
"""

import logging
import re
import Queue
import sys

import dns.resolver

from optparse import OptionParser
from threading import Thread

hosts = Queue.Queue()
answers = Queue.Queue()
ns_re = re.compile(r'^([a-z]{2,})\.\s+\d+\s+IN\s+NS\s+(.*)$')


class Resolver(Thread):
  """A simpler resolver thread which will lookup an type and return answers.

  Args:
    hostsqueue: a Queue.Queue object, the input queue of type/host.
    answersqueue: a Queue.Queue object, where to put host/answer results.
  """
  def __init__(self, hostsqueue, answersqueue):
    self.hostsqueue = hostsqueue
    self.answersqueue = answersqueue
    Thread.__init__(self)

  def lookup(self, qtype, host):
    """Perform the lookup.
 
    Args:
      qtype: a string, the query-type to make
      host: a string, the record to resolve.
    
    Returns:
      RR: a resolver result object.
    """
    rr = []
    try:
      rr = dns.resolver.query(host, qtype)
    except dns.resolver.NoAnswer:
      logging.debug('Failed an %s lookup for %s, err: NoAnswer', qtype, host)
    except dns.resolver.NXDOMAIN:
      logging.debug('Failed an %s lookup for %s, err: NXDOMAIN', qtype, host)
    except dns.exception.Timeout:
      logging.debug('Failed an %s lookup for %s, err: Timeout', qtype, host)
 
    return rr

  def run(self):
    """Start the Thread() loop."""
    while True:
      host_type = self.hostsqueue.get()
      [qtype, host] = host_type.split('/')
      rrSet = self.lookup(qtype, host)
      self.answersqueue.put((host, rrSet))


def readFileContent(zone):
  """Read a zonefile, parse for hosts and zone names.

  Args:
    zone: a filehandle, the file to parse.
  Returns:
    zones: a set of named zones.
    nshosts: a set of all hostnames in the NS sets.
  """
  zones = set()
  nshosts = set()
  for line in zone:
    match = ns_re.match(line)
    if match:
      zones.add(match.group(1))
      nshosts.add(match.group(2))

  return (zones, nshosts)


def parseNS(nsdict):
  """Parse a list of NS host addresses, report on utilization stats.

  Args:
    nsdict: a dict, of the addresses being used as NS hosts
  """
  ipv4 = set()
  ipv4nets = set()
  ipv6 = set()
  ipv6nets = set()
  re_24 = re.compile(r'^(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}$')
  re_48 = re.compile(r'^([a-f0-9]{0,4}:[a-f0-9]{0,4}:[a-f0-9]{0,4}):'
                      '[a-f0-9:]+$')
  for addr in nsdict:
    if ":" in addr:
      ipv6nets.add(addr)
      match = re_48.match(addr)
      if match:
        ipv6.add(match.group(1))
    if '.' in addr:
      ipv4nets.add(addr)
      match = re_24.match(addr)
      if match:
        ipv4.add(match.group(1))

  print 'IPv6 Total Addresses: %s' % len(ipv6nets)
  print 'IPv6 Unique /48s: %s' % len(ipv6)
  print 'IPv4 Total Addresses: %s' % len(ipv4nets)
  print 'IPv4 Unique /24: %s' % len(ipv4)


def main():
  """Main program processing."""
  opts = OptionParser()

  opts.add_option('-d', '--dump', dest='dump', action='store_true',
                  default=False,
                  help='Dump all NS RR host data.')

  opts.add_option('-l', '--log', dest='log', default='/tmp/zone.log',
                  help='Debug logfile location.')

  opts.add_option('-t', '--threads', dest='threads', default=10,
                  help='How many concurrent threads to operate with.')

  opts.add_option('-z', '--zone', dest='zone',
                  help='Zonefile to process.')

  (options, args) = opts.parse_args()

  logging.basicConfig(filename=options.log, level=logging.DEBUG) 

  try:
    zone = open(options.zone)
  except IOError as err:
    print 'Failed to open the zonefile(%s): %s' % (options.zone, err)
    sys.exit(255)

  (zones, nshosts) = readFileContent(zone)

  # Spin up the threads for resolution activities.
  nsaddrs = {}
  nsdict = {}

  for xval in xrange(int(options.threads)):
    resolver = Resolver(hosts, answers)
    resolver.setDaemon(True)
    resolver.start()

  queries = 0
  for host in nshosts:
    hosts.put('A/%s' % host)
    hosts.put('AAAA/%s' % host)
    queries += 2

  count = 0
  while count < queries:
    (host, rr) = answers.get()
    logging.debug('Returned host: %s', host)
    for rdata in rr:
      if host in nsaddrs:
        nsaddrs[host].append(rdata.address)
      else:
        nsaddrs[host] = [rdata.address]

    logging.debug('Count: %s Queries: %s', count, queries)
    count += 1

  for host in nsaddrs:
    for addr in nsaddrs[host]:
      if addr in nsdict:
        nsdict[addr] += 1
      else:
        nsdict[addr] = 1

  print 'Zone count: %s' % len(zones)
  print 'NSHost count: %s' % len(nshosts)
  print 'NSAddr count: %s' % len(nsdict)
  if options.dump:
    print 'All NSAddrs:'
    print 'count\taddress'
    for addr in nsdict:
      print '%s\t%s' % (nsdict[addr], addr)

  print 'Analysis of address usage:'
  parseNS(nsdict)
  

if __name__ == '__main__':
  main()
