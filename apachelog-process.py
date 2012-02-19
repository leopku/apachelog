#!/usr/bin/env python

"""Process Apache (or similarly formated) log files using ``apachelog``.

Use the options to build a parser and list of processors.  Each file
listed on the command line will be parsed by this parser and processed
by each processor.  After processing is complete, interesting
information from each processor will be printed to stdout.
"""

import socket as _socket

from apachelog import __version__
from apachelog.file import open as _open
from apachelog.parser import FORMATS as _FORMATS
from apachelog.parser import Parser as _Parser
from apachelog.processor import process as _process
from apachelog.processor.bandwidth import (
    BandwidthProcessor as _BandwidthProcessor)
from apachelog.processor.bandwidth import (
    IPBandwidthProcessor as _IPBandwidthProcessor)
from apachelog.processor.set import SetProcessor as _SetProcessor
from apachelog.processor.status import StatusProcessor as _StatusProcessor
from apachelog.resolve import Resolver as _Resolver


PROCESSORS = {
    'bandwidth': _BandwidthProcessor,
    'ip-bandwidth': _IPBandwidthProcessor,
    'set': _SetProcessor,
    'status': _StatusProcessor,
    }


def display_processor(processor, **kwargs):
    for name,type_ in PROCESSORS.items():
        if type(processor) == type_:
            pname = name.replace('-', '_')
            display = globals()['display_{}'.format(pname)]
            return display(processor=processor, **kwargs)

def display_bandwidth(stream, processor, args, **kwargs):
    scale = args.scale
    stream.write('# IP bandwidth ({})\n'.format(scale))
    stream.write('{}\n'.format(processor.bandwidth(scale=scale)))

def display_ip_bandwidth(stream, processor, resolver, args):
    scale = args.scale
    top = args.top
    stream.write('# IP bandwidth ({})\n'.format(scale))
    if resolver is not None:
        processor.resolve(resolver=resolver, top=top)
    remaining = processor.bandwidth(scale=scale)
    for ip,bw in processor.ip_bandwidth(
        scale=scale, sort_by_bandwidth=True)[-1:-top:-1]:
        remaining -= bw
        stream.write('\t'.join([str(bw), ip]))
        if resolver is not None:  # also print the raw IPs
            ips = resolver.ips(ip)
            try:
                ips.remove(ip)
            except KeyError:
                pass
            stream.write('\t{}'.format(' '.join(sorted(ips))))
        stream.write('\n')
    stream.write('\t'.join([str(remaining), 'REMAINING']))
    stream.write('\n')

def display_set(stream, processor, **kwargs):
    stream.write('# Value sets\n')
    for key,values in sorted(processor.values.items()):
        stream.write('{}\n'.format(key))
        for value in sorted(values):
            stream.write('\t{}\n'.format(value))

def display_status(stream, processor, **kwargs):
    stream.write('# Status\n')
    for request,status in sorted(processor.request.items()):
        stream.write('\t'.join([request, ', '.join(sorted(status))]))
        stream.write('\n')
    for status,request in sorted(processor.status.items()):
        stream.write('{}\n'.format(status))
        for r in sorted(request):
            stream.write('\t{}\n'.format(r))


if __name__ == '__main__':
    import argparse
    import sys

    parser = argparse.ArgumentParser(description=__doc__, version=__version__)
    parser.add_argument(
        '-f', '--format', default='common',
        help='Log format string, or one of the predefined formats: {}'.format(
            ', '.join(sorted(_FORMATS.keys()))))
    for processor in sorted(PROCESSORS.keys()):
        parser.add_argument(
            '--{}'.format(processor), default=False, action='store_const',
            const=True,
            help='Use the {} processor'.format(processor))
    parser.add_argument(
        '-r', '--resolve', default=False, action='store_const', const=True,
        help='Resolve IP addresses for bandwidth measurements')
    parser.add_argument(
        '-t', '--top', default=10, type=int,
        help='Number of IPs to print for ip-bandwidth measurements')
    parser.add_argument(
        '-s', '--scale', default='MB/month',
        choices=sorted(_BandwidthProcessor._scales.keys()),
        help='Scale for the bandwidth processors')
    parser.add_argument(
        '-k', '--key', action='append', help='Add a key to the set processor')
    parser.add_argument(
        'file', nargs='+', help='Path to log file')

    args = parser.parse_args()

    if hasattr(_socket, 'setdefaulttimeout'):
        _socket.setdefaulttimeout(5)  # set 5 second timeout

    fmt = _FORMATS.get(args.format, args.format)
    parser = _Parser(fmt)

    if args.resolve:
        resolver = _Resolver(smart=True)
    else:
        resolver = None

    processors = []
    for processor in sorted(PROCESSORS.keys()):
        pattr = processor.replace('-', '_')
        if not getattr(args, pattr):
            continue
        kwargs = {}
        if pattr == 'set':
            kwargs['keys'] = args.key
        p = PROCESSORS[processor](**kwargs)
        processors.append(p)

    for filename in args.file:
        with _open(filename) as f:
            _process(stream=f, parser=parser, processors=processors)
    for processor in processors:
        display_processor(
            stream=sys.stdout, processor=processor, resolver=resolver,
            args=args)
        if processor != processors[-1]:
            print ''  # blank line between output blocks
