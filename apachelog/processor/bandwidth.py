from __future__ import division

import datetime as _datetime

from .time import LogTimeProcessor as _LogTimeProcessor


class BandwidthProcessor (_LogTimeProcessor):
    r"""Track the total bandwith for the processed log files.

    >>> import StringIO
    >>> from apachelog.parser import Parser, FORMATS
    >>> from apachelog.processor import process
    >>> stream = StringIO.StringIO('\n'.join([
    ...         '192.168.0.1 - - [18/Feb/2012:10:25:43 -0500] "GET / HTTP/1.1" 200 560 "-" "Mozilla/5.0 (...)"',
    ...         '192.168.0.2 - - [18/Feb/2012:10:25:58 -0500] "GET / HTTP/1.1" 200 560 "-" "Mozilla/5.0 (...)"',
    ...         ]))
    >>> parser = Parser(FORMATS['extended'])
    >>> bwp = BandwidthProcessor()
    >>> process(stream, parser, [bwp])
    >>> bwp.bandwidth(scale='MB/month')
    193.536
    """
    _scales = {
        'B/s': 1,
        'kB/s': 1e-3,
        'MB/s': 1e-6,
        'MB/month': 1e-6*_datetime.timedelta(days=30).total_seconds(),
        }

    def __init__(self, **kwargs):
        super(BandwidthProcessor, self).__init__(**kwargs)
        self.bytes = 0
        self.last_bytes = None

    def process(self, data):
        super(BandwidthProcessor, self).process(data)
        self.last_bytes = None  # for use by subclasses
        try:
            self.last_bytes = int(data['%b'])  # excludes HTTP headers
        except ValueError:
            return
        self.bytes += self.last_bytes

    def bandwidth(self, scale='kB/s', _bytes=None):
        """
        The `_bytes` argument is for use by subclasses.
        """
        sec = self.total_seconds()
        if sec == 0:
            return 0
        if _bytes is None:
            _bytes = self.bytes
        s = self._scales[scale]
        return s * _bytes / sec


class IPBandwidthProcessor (BandwidthProcessor):
    r"""Track the bandwith per-IP for the processed log files.

    >>> import StringIO
    >>> from apachelog.parser import Parser, FORMATS
    >>> from apachelog.processor import process
    >>> stream = StringIO.StringIO('\n'.join([
    ...         '192.168.0.1 - - [18/Feb/2012:10:25:43 -0500] "GET / HTTP/1.1" 200 560 "-" "Mozilla/5.0 (...)"',
    ...         '192.168.0.1 - - [18/Feb/2012:10:25:43 -0500] "GET /style.css HTTP/1.1" 200 8240 "-" "Mozilla/5.0 (...)"',
    ...         '192.168.0.2 - - [18/Feb/2012:10:25:58 -0500] "GET / HTTP/1.1" 200 560 "-" "Mozilla/5.0 (...)"',
    ...         ]))
    >>> parser = Parser(FORMATS['extended'])
    >>> bwp = IPBandwidthProcessor()
    >>> process(stream, parser, [bwp])
    >>> for ip,bw in bwp.ip_bandwidth(
    ...         scale='MB/month', sort_by_bandwidth=True):
    ...     print('\t'.join([ip, str(bw)]))  # doctest: +NORMALIZE_WHITESPACE
    192.168.0.2 96.768
    192.168.0.1 1520.64

    Sometimes you want to consolidate IPs using the smart-resolution
    of the ``Resolver`` class.

    >>> from apachelog.resolve import Resolver
    >>> r = Resolver(smart=True)

    We're going to fake the resolver values for this test.

    >>> r.IP['192.168.0.1'] = ('testbot', [], ['192.168.0.1', '192.168.0.2'])
    >>> r.IP['192.168.0.2'] = r.IP['192.168.0.1']

    Resolve the top IPs until we explain 50% of the total data.

    >>> bwp.resolve(r, minimum_total=0.5)
    >>> for ip,bw in bwp.ip_bandwidth(
    ...         scale='MB/month', sort_by_bandwidth=True):
    ...     print('\t'.join([ip, str(bw)]))  # doctest: +NORMALIZE_WHITESPACE
    192.168.0.2 96.768
    testbot     1520.64

    Resolve the top 10 clients.  Note that if smart resolution merges
    hosts (i.e. multiple Googlebot IPs), there may be more than 10
    calls to the resolver.

    >>> bwp.resolve(r, top=10)
    >>> for ip,bw in bwp.ip_bandwidth(
    ...         scale='MB/month', sort_by_bandwidth=True):
    ...     print('\t'.join([ip, str(bw)]))  # doctest: +NORMALIZE_WHITESPACE
    testbot     1617.408
    """
    def __init__(self, **kwargs):
        super(IPBandwidthProcessor, self).__init__(**kwargs)
        self.ip_bytes = {}

    def process(self, data):
        super(IPBandwidthProcessor, self).process(data)
        if self.last_bytes:
            ip = data['%h']
            self.ip_bytes[ip] = self.last_bytes + self.ip_bytes.get(ip, 0)

    def resolve(self, resolver, top=None, minimum_total=None):
        resolved = set()
        remaining = self.bytes
        if minimum_total is not None:
            target_rem = minimum_total*self.bytes
        ip_bw = self.ip_bandwidth(sort_by_bandwidth=True)
        for ip,bw in reversed(ip_bw):
            if top is not None and len(resolved) > top:
                break
            if minimum_total is not None and remaining < target_rem:
                break
            remaining -= self.ip_bytes[ip]
            rip = resolver.resolve(ip)
            resolved.add(rip)
            if rip != ip:
                b = self.ip_bytes.pop(ip)
                self.ip_bytes[rip] = b + self.ip_bytes.get(rip, 0)

    def ip_bandwidth(self, sort_by_bandwidth=False, **kwargs):
        """Return a ``name`` -> ``bandwidth`` dictionary.

        If ``sort_by_bandwidth`` is ``True``, return a list of
        ``(name, bandwidth)`` tuples (instead of the dictionary).  The
        list will be sorted in order of increasing bandwidth.

        If you want to consolidate entries by several IPs representing
        the same entity (e.g. Googlebot), you'll want to run the
        ``resolve`` method before calling this one.
        """
        if sort_by_bandwidth:
            ip_bw = self.ip_bandwidth(**kwargs)
            bw_ip = sorted((bw,ip) for ip,bw in ip_bw.items())
            return [(k,b) for b,k in bw_ip]
        return dict((k,self.bandwidth(_bytes=b, **kwargs))
                    for k,b in self.ip_bytes.items())

