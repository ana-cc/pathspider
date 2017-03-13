# -*- coding: utf-8 -*-

'''
Resolution: Resolve a large number of domains to IPv4 and IPv6 addresses.

.. moduleauthor:: Damiano Boppart <hat.guy.repo@gmail.com>

Copyright 2014 Damiano Boppart

This file is part of ECN-Spider.
'''

import sys
import dns.resolver
import csv
import queue
import threading
import datetime
import logging

TIMEOUT = None  #: The timeout for DNS resolution.
SLEEP = None  #: Time to sleep before each resolution, for crude rate-limiting.
WWW = None  #: The value of the -www command line option

Q_SIZE = 100  #: Maximum domain queue size


def resolve(domain, query='A', max_tries=3):
    '''
    Resolve a domain name to IP address(es).

    :param str domain: The domain to be resolved.
    :param str query: The query type. May be either 'A' or 'AAAA'.
    :param int max_tries: Number of times to try a lookup when a Timeout occurs
    :returns: A list of IP addresses as strings.
    :throws: Instances of ``dns.exception``
    '''
    resolver = dns.resolver.Resolver()
    resolver.lifetime = TIMEOUT

    while max_tries > 0:
        try:
            answer = resolver.query(domain, query)
        except dns.exception.Timeout:
            # Just a timeout, lets try again
            max_tries = max_tries - 1
            continue
        except dns.exception.DNSException:
            answer = None
            break
        else:
            # if there would have been no answer, then the Resolver() would have
            # raised a DNSException, so we know that there answer has content.
            answer = [a.to_text() for a in answer]
            # answer now is an array of strings of ip's
            break    

    if max_tries <= 0: return None
    return answer


def resolve_both(domain):
    '''
    Gets all A and AAAA records for domain
    '''
    a = resolve(domain, 'A')
    a4 = resolve(domain, 'AAAA')
    
    return (a, a4)


def csv_gen(skip=0, count=0, *args, **kwargs):
    '''
    A wrapper around :meth:`csv.reader`, that makes it a generator.

    :meth:`csv_gen` does not return entire records, instead it extracts
           one particular field from a record.

    :param \\*args: Arguments passed to :meth:`csv.reader`.
    :param \\*\\*kwargs: Keyword arguments passed to :meth:`csv.reader`.
    :returns: One field from each record on each call to :meth:`next()`.
    '''
    logger = logging.getLogger('dnsresolv')
    reader = csv.reader(*args, **kwargs)

    # Discard the first entries
    for _ in range(skip):
        next(reader)

    c = 0
    for row in reader:
        yield row
        c += 1
        if c % 1000 == 0:
            logger.info('Parsed %d records so far.', c)
        if count != 0 and c >= count:
            break

def resolution_worker(iq, oq, only_first=False):
    logger = logging.getLogger('dnsresolv')
    
    while True:
        entry = iq.get()

        # Shutdown and cascade
        if entry is None:
            logger.debug("Resolution worker shutting down")
            iq.task_done()
            break
 
        try:
            rank = entry[0]
            domain = entry[1]
        except IndexError: 
            logger.error("Badly formated input line: %s", entry)
            iq.task_done()
            continue

        try:

            # NOTE www.com or www.co.uk would be incorrectly handled by
            # checking for a leading "www." first. Alexa's list generally omits
            # the almost ubiquitous "www.", but not always: www.uk.com is a
            # counter-example.
            
            #wdomain = domain
            #if domain[:4] != 'www.':
                #wdomain = 'www.' + domain
            
            wdomain = 'www.' + domain

            # ``domain`` is the 'original' passed in, and ``wdomain`` is domain
            # with a 'www.' prepended to it.

            ## FIRST: try to get all the DNS records we want

            #initalise all results to None:
            a, a4, aw, a4w = None, None, None, None

            if WWW == 'never':
                (a, a4) = resolve_both(domain)
            elif WWW == 'always':
                (aw, a4w) = resolve_both(wdomain)
            elif WWW == 'both':
                (a, a4) = resolve_both(domain)
                (aw, a4w) = resolve_both(wdomain)
            elif WWW == 'preferred':
                # first, lets try to resolve the wdomain
                (aw, a4w) = resolve_both(wdomain)
                # now, if we didn't get an A or AAAA record, 
                # try to get if for the domain
                if aw == None:
                    a = resolve(domain, 'A')
                if a4w == None:
                    a4 = resolve(domain, 'AAAA')
            else:
                logger.error("Internal error: illegal WWW value")
                sys.exit(1)

    
            ## SECOND: see what records we received, and process them

            if a != None:
                for record in a:
                    oq.put((record, domain, rank))
                    if only_first: break
            if a4 != None:
                for record in a4:
                    oq.put((record, domain, rank))
                    if only_first: break
            if aw != None:
                for record in aw:
                    oq.put((record, wdomain, rank))
                    if only_first: break
            if a4w != None:
                for record in a4w:
                    oq.put((record, wdomain, rank))
                    if only_first: break

        except Exception as e:
            logger.warning("Discarding resolution for "+domain+": "+repr(e))
        finally:
            iq.task_done()

def add_port_number(entry, port):
    '''
    Add a port number to an entry
    
    Transforms an entry from (ip, domain, rank) to (ip, <port>, domain, rank)
    if port is not None
    '''
    
    if port == None:
        return entry

    return (entry[0], port) + entry[1:]

def check_if_unique_ip(entry, set_of_ips):
    """
    Checks if an entry contains an IP that was not encountered before

    Checks if the IP of `entry` is in `set_of_ips` already,
    and if not, adds the IP of `entry` to `set_of_ips`

    Returns `True` if the IP of `entry` was not yet in `set_of_ips`

    entry: tuple of which element zero should be an IP address
    set_of_ips: set of IP's that where previously seen
    """

    if entry[0] in set_of_ips:
        return False
    set_of_ips.add(entry[0])
    return True

def output_worker(oq, writer, add_port, unique_ip=False):
    logger = logging.getLogger('dnsresolv')

    logger.info("output thread started")
    processed_ips = set()
    while True:
        entry = oq.get()

        if entry is None:
            logger.info("Output handling shutdown signal")
            oq.task_done()
            break
        
        if unique_ip == True:
            if not check_if_unique_ip(entry, processed_ips):
                continue

        entry = add_port_number(entry, add_port)
        writer.writerow(entry)
        oq.task_done()

def main(args):
    '''
    Run the resolver.
    '''
    logger = logging.getLogger('dnsresolv')

    # Some validation
    if args.workers <= 0:
        raise ValueError('Workers must be a positive integer, ' 
        'it was set to {}.'.format(args.workers))
    if args.sleep < 0:
        raise ValueError('Sleep must be a non-negative float, '
        'it was set to {}.'.format(args.sleep))
    if args.timeout <= 0:
        raise ValueError('Timeout must be a positive integer, '
        'it was set to {}.'.format(args.timeout))
    if args.debug_skip < 0:
        raise ValueError('Debug-skip must be a non-negative integer, '
        'it was set to {}.'.format(args.debug_skip))
    if args.debug_count < 0:
        raise ValueError('Debug-count must be a non-negative integer, '
        'it was set to {}.'.format(args.debug_count))

    global TIMEOUT
    TIMEOUT = args.timeout

    global WWW
    WWW = args.www

    global SLEEP
    SLEEP = args.sleep

    with open(args.input) as inf, open(args.output, 'w', newline='') as ouf:
        logger.debug('Opening input file.')
        reader = csv_gen(args.debug_skip, args.debug_count, inf)
        logger.debug('Opening output file.')
        writer = csv.writer(ouf)

        t0 = datetime.datetime.now()  # Start time of resolution
        tl = t0  # Time since last printed message

        iq = queue.Queue(Q_SIZE)
        oq = queue.Queue(Q_SIZE)
        ts = {}

        logger.info('Starting worker threads...')
        for i in range(args.workers):
            t = threading.Thread(target=resolution_worker,
                    name='worker_{}'.format(i), args=(iq, oq, args.only_first),
                    daemon=True)
            t.start()
            ts[t.name] = t

        logger.info('Starting output thread...')
        ot = threading.Thread(target=output_worker, name='output_worker',
                args=(oq, writer, args.add_port, args.unique_ip), daemon=True)
        ot.start()

        logger.info('Enqueueing domains...')

        for dc, d in enumerate(reader):
            iq.put(d)
            if (dc + 1) % 1000 == 0:
                tt = datetime.datetime.now()
                current_rate = float(1000) / (tt - tl).total_seconds()
                average_rate = float(dc+1) / (tt - t0).total_seconds()
                tl = tt
                logstring = ('Enqueued {num_dom:>6} domains. '
                             'Rate: {cur:9.2f} Hz. Average rate: {avg:9.2f} Hz.')
                logger.info(logstring.format(num_dom=dc+1, cur=current_rate,
                        avg=average_rate))

        # now enqueue a quit signal, one for each worker
        for i in range(args.workers):
            iq.put(None)

        # wait for queues to drain
        logger.info('Sent shtudown signal to all resolution workers')
        iq.join()
        logger.info('All resolution workers have shut down')
        logger.info('Sending shut down signal to output worker')
        oq.put(None)
        ot.join()
        logger.info('Output worker has shut down')

    t1 = datetime.datetime.now()
    time = t1 - t0
    average_rate = float(dc+1) / time.total_seconds()
    logger.info('Resolution completed.')
    logstring = ('Resolved {num_dom} domains. Total time: {time}. Average rate: '
                 '{avg:.2f} domains per second.')
    logger.info(logstring.format(num_dom=dc+1, time=time, avg=average_rate))

def register_args(subparsers):
    parser = subparsers.add_parser('dnsresolv',
            help='DNS resolution for hostnames to IPv4 and v6 addresses')
    parser.set_defaults(func=main)

    # FIXME use type=argparse.FileType() here
    #parser.add_argument('input_file', type=str,
    #       help='CSV format input data file with one domain per line. '
    #       'The domain must be in one field of a record, that record is '
    #       'selected with the "position" argument.')
    #parser.add_argument('output_file', type=str,
    #       help='CSV format output data file with domain names and associated '
    #       'IP addresses. Each record has the format: "domain,IPv4,IPv6".')

    #parser.add_argument('--workers', '-w', type=int, default='5',
    #        help='The number of worker threads used for resolution.')
    parser.add_argument('--timeout', '-t', type=int, default='10',
            help='Timeout for DNS resolution.')
    
    parser.add_argument('--sleep', '-s', type=float, default='0',
            help='Sleep before every request. Useful for rate-limiting.')
    
    parser.add_argument('--add-port', '-p', type=int, default=None,
            dest='add_port',
            help='If specified, this port number will be added to every'
            ' line in the output file.')

    parser.add_argument('--only-first', default=False,
            action='store_true', dest='only_first',
            help='Only process the first record of every DNS querry.'
            ' If this is true, at most one A and and one AAAA record will'
            ' be returned for every domain')

    parser.add_argument('--unique-ip', default=False,
            action='store_true', dest='unique_ip',
            help='If set, any output entries with duplicate IP addresses '
            'will be discarded')

    parser.add_argument('--www', default='preferred',
            choices=['never', 'preferred', 'always', 'both'],
            help='Mode for prepending "www." to every domain before resolution.'
            ' "never" will never prepend "www.". "preferred" will prepend '
            '"www." if the resolution of the domain including "www." '
            'is successful (more specifically: an A record is returned), '
            'and otherwise fall back to omitting the "www.". "always" will '
            'prepend "www." and will return no IP address in the output file, '
            'even when the domain without "www." can be resolved to one. '
            '"both" behaves as "always" and "never" together, that is, it '
            'resolves each domain with and without a prepended "www.". '
            'All values for this option will never stack the www\'s, that is '
            '"www.example.com" will never be expanded to "www.www.example.com".'
            ' An existing "www." prefix from a domain from the input file will '
            'never be dropped. If this value is not "never", then the output '
            'file may contain different FQDNs from the input file, as '
            '"example.com" might be turned into "www.example.com".')

    parser.add_argument('--debug-skip', type=int, default='0',
             dest='debug_skip',
             help='Skip the first N domains, and do not resolve them.')
    
    parser.add_argument('--debug-count', type=int, default='0', 
            dest='debug_count',
            help='Perform resolution for at most N domains. '
                    'All of them if this value is set to 0.')

