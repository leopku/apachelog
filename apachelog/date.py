"""
The `parse_date` function is intended as a fast way to convert a log
date into something useful, without incurring a significant date
parsing overhead---good enough for basic stuff but will be a problem
if you need to deal with log from multiple servers in different
timezones.
"""


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
    to the timezone---this is your problem.
    """
    date = date[1:-1]
    elems = [
        date[7:11],
        MONTHS[date[3:6]],
        date[0:2],
        date[12:14],
        date[15:17],
        date[18:20],
        ]
    return (''.join(elems),date[21:])
