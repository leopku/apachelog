"""Utilities for parsing the request time field (``%t``).

The ``parse_date`` function is intended as a fast way to convert a log
date into something useful, without incurring a significant date
parsing overhead---good enough for basic stuff but will be a problem
if you need to deal with log from multiple servers in different
timezones.

An alternative funtion, ``parse_time``, parses the data into
``datetime.datetime`` instances, which may be slower, but it does take
the offset into account.  It also makes it easy to calculate time
differences.
"""

import datetime as _datetime


MONTHS = {
    'Jan':'01',
    'Feb':'02',
    'Mar':'03',
    'Apr':'04',
    'May':'05',
    'Jun':'06',
    'Jul':'07',
    'Aug':'08',
    'Sep':'09',
    'Oct':'10',
    'Nov':'11',
    'Dec':'12'
    }


def parse_date(date):
    """Convert a date to a (`timestamp`, `offset`) tuple.

    Takes a date in the format: [05/Dec/2006:10:51:44 +0000]
    (including square brackets) and returns a two element
    tuple containing first a timestamp of the form
    YYYYMMDDHH24IISS e.g. 20061205105144 and second the
    timezone offset as is e.g.;

    >>> parse_date('[05/Dec/2006:10:51:44 +0000]')
    ('20061205105144', '+0000')

    It does not attempt to adjust the timestamp according
    to the timezone---if you need this, use ``parse_time``.
    """
    date = date.strip('[]')
    elems = [
        date[7:11],
        MONTHS[date[3:6]],
        date[0:2],
        date[12:14],
        date[15:17],
        date[18:20],
        ]
    return (''.join(elems),date[21:])


class FixedOffset(_datetime.tzinfo):
    """Fixed offset in minutes east from UTC.

    >>> f = FixedOffset(name='-0500', hours=-5)
    >>> f.utcoffset(dt=None)
    datetime.timedelta(-1, 68400)
    >>> (24-5)*60*60
    68400
    >>> f.tzname(dt=None)
    '-0500'
    >>> f.dst(dt=None)
    datetime.timedelta(0)
    """
    _ZERO = _datetime.timedelta(0)

    def __init__(self, name, **kwargs):
        self._offset = _datetime.timedelta(**kwargs)
        self._name = name

    def utcoffset(self, dt):
        return self._offset

    def tzname(self, dt):
        return self._name

    def dst(self, dt):
        return self._ZERO

def parse_time(date):
    """
    >>> import time
    >>> dt = parse_time("[12/Feb/2012:09:55:33 -0500]")
    >>> dt.isoformat()
    '2012-02-12T09:55:33-05:00'
    >>> time.mktime(dt.utctimetuple())
    1329076533.0
    """
    date = date.strip('[]')
    tzdate = date[21:].strip()
    soff = int(date[21:22] + '1')
    hoff = int(date[22:24])
    moff = int(date[24:])
    tz = FixedOffset(tzdate, hours=soff*hoff, minutes=soff*moff)
    return _datetime.datetime(
        year=int(date[7:11]),
        month=int(MONTHS[date[3:6]]),
        day=int(date[0:2]),
        hour=int(date[12:14]),
        minute=int(date[15:17]),
        second=int(date[18:20]),
        microsecond=int(0),
        tzinfo=tz)
