r"""Apache Log Parser

Parser for Apache log files. This is a port to python of Peter Hickman's
`Apache::LogEntry Perl module`__.

.. __: http://cpan.uwinnipeg.ca/~peterhi/Apache-LogRegex

Takes the `Apache logging format`__ defined in your ``httpd.conf`` and
generates a regular expression which is used to a line from the log
file and return it as a dictionary with keys corresponding to the
fields defined in the log format.

.. __: http://httpd.apache.org/docs/current/mod/mod_log_config.html#formats

Import libraries used in the example:

>>> import apachelog.parser, sys, StringIO, pprint

You should generally be able to copy and paste the format string from
your Apache configuration, but remember to place it in a raw string
using single-quotes, so that backslashes are handled correctly.

>>> format = r'%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"'
>>> p = apachelog.parser.Parser(format)

Now open your log file.  For this example, we'll fake a log file with
``StringIO``.

>>> #log_stream = open('/var/apache/access.log')
>>> log_stream = StringIO.StringIO('\n'.join([
...         '192.168.0.1 - - [18/Feb/2012:10:25:43 -0500] "GET / HTTP/1.1" 200 561 "-" "Mozilla/5.0 (...)"',
...         'junk line',
...         ]))
>>> for line in log_stream:
...     try:
...         data = p.parse(line)
...     except:
...         print("Unable to parse %s" % line.rstrip())
...     else:
...         pprint.pprint(data)
{'%>s': '200',
 '%b': '561',
 '%h': '192.168.0.1',
 '%l': '-',
 '%r': 'GET / HTTP/1.1',
 '%t': '[18/Feb/2012:10:25:43 -0500]',
 '%u': '-',
 '%{Referer}i': '-',
 '%{User-Agent}i': 'Mozilla/5.0 (...)'}
Unable to parse junk line

The return dictionary from the parse method has values for each
directive in the format string.

You can also re-map the field names by subclassing (or clobbering) the
alias method.

This module provides three of the most common log formats in the
formats dictionary;

>>> # Common Log Format (CLF)
>>> p = apachelog.parser.Parser(apachelog.parser.FORMATS['common'])
>>> # Common Log Format with Virtual Host
>>> p = apachelog.parser.Parser(apachelog.parser.FORMATS['vhcommon'])
>>> # NCSA extended/combined log format
>>> p = apachelog.parser.Parser(apachelog.parser.FORMATS['extended'])

For some older notes regarding performance while reading lines from a
file in Python, see `this post`__ by Fredrik Lundh.  Further
performance boost can be gained by using psyco_.

.. __: http://effbot.org/zone/readline-performance.htm
.. _psycho: http://psyco.sourceforge.net/

On my system, using a loop like::

    for line in open('access.log'):
        p.parse(line)

was able to parse ~60,000 lines / second. Adding psyco to the mix,
up that to ~75,000 lines / second.
"""

__version__ = "1.2"
__license__ = """Released under the same terms as Perl.
See: http://dev.perl.org/licenses/
"""
__author__ = "Harry Fuecks <hfuecks@gmail.com>"
__contributors__ = [
    "Peter Hickman <peterhi@ntlworld.com>",
    "Loic Dachary <loic@dachary.org>",
    "W. Trevor King <wking@drexel.edu>",
    ]
