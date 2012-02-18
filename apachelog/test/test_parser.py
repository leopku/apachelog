import unittest

from ..parser import ApacheLogParserError, parser, formats


class TestApacheLogParser(unittest.TestCase):

    def setUp(self):
        self.format = r'%h %l %u %t \"%r\" %>s '\
                      r'%b \"%{Referer}i\" \"%{User-Agent}i\"'
        self.fields = '%h %l %u %t %r %>s %b %{Referer}i '\
                      '%{User-Agent}i'.split(' ')
        self.pattern = '^(\\S*) (\\S*) (\\S*) (\\[[^\\]]+\\]) '\
                       '\\\"([^"\\\\]*(?:\\\\.[^"\\\\]*)*)\\\" '\
                       '(\\S*) (\\S*) \\\"([^"\\\\]*(?:\\\\.[^"\\\\]*)*)\\\" '\
                       '\\\"([^"\\\\]*(?:\\\\.[^"\\\\]*)*)\\\"$'
        self.line1  = r'212.74.15.68 - - [23/Jan/2004:11:36:20 +0000] '\
                      r'"GET /images/previous.png HTTP/1.1" 200 2607 '\
                      r'"http://peterhi.dyndns.org/bandwidth/index.html" '\
                      r'"Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.2) '\
                      r'Gecko/20021202"'
        self.line2  = r'212.74.15.68 - - [23/Jan/2004:11:36:20 +0000] '\
                      r'"GET /images/previous.png=\" HTTP/1.1" 200 2607 '\
                      r'"http://peterhi.dyndns.org/bandwidth/index.html" '\
                      r'"Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.2) '\
                      r'Gecko/20021202"'
        self.line3  = r'4.224.234.46 - - [20/Jul/2004:13:18:55 -0700] '\
                      r'"GET /core/listing/pl_boat_detail.jsp?&units=Feet&checked'\
                      r'_boats=1176818&slim=broker&&hosturl=giffordmarine&&ywo='\
                      r'giffordmarine& HTTP/1.1" 200 2888 "http://search.yahoo.com/'\
                      r'bin/search?p=\"grady%20white%20306%20bimini\"" '\
                      r'"\"Mozilla/4.0 (compatible; MSIE 6.0; Windows 98; '\
                      r'YPC 3.0.3; yplus 4.0.00d)\""'
#                          r'"Mozilla/4.0 (compatible; MSIE 6.0; Windows 98; '\
#                          r'YPC 3.0.3; yplus 4.0.00d)"'
        self.p = parser(self.format)

    def testpattern(self):
        self.assertEqual(self.pattern, self.p.pattern())

    def testnames(self):
        self.assertEqual(self.fields, self.p.names())

    def testline1(self):
        data = self.p.parse(self.line1)
        self.assertEqual(data['%h'], '212.74.15.68', msg = 'Line 1 %h')
        self.assertEqual(data['%l'], '-', msg = 'Line 1 %l')
        self.assertEqual(data['%u'], '-', msg = 'Line 1 %u')
        self.assertEqual(data['%t'], '[23/Jan/2004:11:36:20 +0000]', msg = 'Line 1 %t')
        self.assertEqual(
            data['%r'],
            'GET /images/previous.png HTTP/1.1',
            msg = 'Line 1 %r'
            )
        self.assertEqual(data['%>s'], '200', msg = 'Line 1 %>s')
        self.assertEqual(data['%b'], '2607', msg = 'Line 1 %b')
        self.assertEqual(
            data['%{Referer}i'],
            'http://peterhi.dyndns.org/bandwidth/index.html',
            msg = 'Line 1 %{Referer}i'
            )
        self.assertEqual(
            data['%{User-Agent}i'],
            'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.2) Gecko/20021202',
            msg = 'Line 1 %{User-Agent}i'
            )


    def testline2(self):
        data = self.p.parse(self.line2)
        self.assertEqual(data['%h'], '212.74.15.68', msg = 'Line 2 %h')
        self.assertEqual(data['%l'], '-', msg = 'Line 2 %l')
        self.assertEqual(data['%u'], '-', msg = 'Line 2 %u')
        self.assertEqual(
            data['%t'],
            '[23/Jan/2004:11:36:20 +0000]',
            msg = 'Line 2 %t'
            )
        self.assertEqual(
            data['%r'],
            r'GET /images/previous.png=\" HTTP/1.1',
            msg = 'Line 2 %r'
            )
        self.assertEqual(data['%>s'], '200', msg = 'Line 2 %>s')
        self.assertEqual(data['%b'], '2607', msg = 'Line 2 %b')
        self.assertEqual(
            data['%{Referer}i'],
            'http://peterhi.dyndns.org/bandwidth/index.html',
            msg = 'Line 2 %{Referer}i'
            )
        self.assertEqual(
            data['%{User-Agent}i'],
            'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.2) Gecko/20021202',
            msg = 'Line 2 %{User-Agent}i'
            )

    def testline3(self):
        data = self.p.parse(self.line3)
        self.assertEqual(data['%h'], '4.224.234.46', msg = 'Line 3 %h')
        self.assertEqual(data['%l'], '-', msg = 'Line 3 %l')
        self.assertEqual(data['%u'], '-', msg = 'Line 3 %u')
        self.assertEqual(
            data['%t'],
            '[20/Jul/2004:13:18:55 -0700]',
            msg = 'Line 3 %t'
            )
        self.assertEqual(
            data['%r'],
            r'GET /core/listing/pl_boat_detail.jsp?&units=Feet&checked_boats='\
            r'1176818&slim=broker&&hosturl=giffordmarine&&ywo=giffordmarine& '\
            r'HTTP/1.1',
            msg = 'Line 3 %r'
            )
        self.assertEqual(data['%>s'], '200', msg = 'Line 3 %>s')
        self.assertEqual(data['%b'], '2888', msg = 'Line 3 %b')
        self.assertEqual(
            data['%{Referer}i'],
            r'http://search.yahoo.com/bin/search?p=\"grady%20white%20306'\
            r'%20bimini\"',
            msg = 'Line 3 %{Referer}i'
            )
        self.assertEqual(
            data['%{User-Agent}i'],
            '\\"Mozilla/4.0 (compatible; MSIE 6.0; Windows 98; YPC 3.0.3; '\
            'yplus 4.0.00d)\\"',
#                'Mozilla/4.0 (compatible; MSIE 6.0; Windows 98; YPC 3.0.3; '\
#                'yplus 4.0.00d)',
            msg = 'Line 3 %{User-Agent}i'
            )


    def testjunkline(self):
        self.assertRaises(ApacheLogParserError,self.p.parse,'foobar')

    def testhasquotesaltn(self):
        p = parser(r'%a \"%b\" %c')
        line = r'foo "xyz" bar'
        data = p.parse(line)
        self.assertEqual(data['%a'],'foo', '%a')
        self.assertEqual(data['%b'],'xyz', '%c')
        self.assertEqual(data['%c'],'bar', '%c')

class TestApacheLogParserFriendlyNames(unittest.TestCase):

    def setUp(self):
        self.format = r'%h %l %u %t \"%r\" %>s '\
                      r'%b \"%{Referer}i\" \"%{User-Agent}i\"'
        self.fields = ('remote_host remote_logname remote_user time '
                       'first_line last_status response_bytes_clf '
                       'header_Referer header_User_Agent').split(' ')
        self.pattern = '^(\\S*) (\\S*) (\\S*) (\\[[^\\]]+\\]) '\
                       '\\\"([^"\\\\]*(?:\\\\.[^"\\\\]*)*)\\\" '\
                       '(\\S*) (\\S*) \\\"([^"\\\\]*(?:\\\\.[^"\\\\]*)*)\\\" '\
                       '\\\"([^"\\\\]*(?:\\\\.[^"\\\\]*)*)\\\"$'
        self.line1  = r'212.74.15.68 - - [23/Jan/2004:11:36:20 +0000] '\
                      r'"GET /images/previous.png HTTP/1.1" 200 2607 '\
                      r'"http://peterhi.dyndns.org/bandwidth/index.html" '\
                      r'"Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.2) '\
                      r'Gecko/20021202"'
        self.line2  = r'212.74.15.68 - - [23/Jan/2004:11:36:20 +0000] '\
                      r'"GET /images/previous.png=\" HTTP/1.1" 200 2607 '\
                      r'"http://peterhi.dyndns.org/bandwidth/index.html" '\
                      r'"Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.2) '\
                      r'Gecko/20021202"'
        self.line3  = r'4.224.234.46 - - [20/Jul/2004:13:18:55 -0700] '\
                      r'"GET /core/listing/pl_boat_detail.jsp?&units=Feet&checked'\
                      r'_boats=1176818&slim=broker&&hosturl=giffordmarine&&ywo='\
                      r'giffordmarine& HTTP/1.1" 200 2888 "http://search.yahoo.com/'\
                      r'bin/search?p=\"grady%20white%20306%20bimini\"" '\
                      r'"\"Mozilla/4.0 (compatible; MSIE 6.0; Windows 98; '\
                      r'YPC 3.0.3; yplus 4.0.00d)\""'
#                          r'"Mozilla/4.0 (compatible; MSIE 6.0; Windows 98; '\
#                          r'YPC 3.0.3; yplus 4.0.00d)"'
        self.p = parser(self.format, True)

    def testpattern(self):
        self.assertEqual(self.pattern, self.p.pattern())

    def testnames(self):
        self.assertEqual(self.fields, self.p.names())

    def testline1(self):
        data = self.p.parse(self.line1)
        self.assertEqual(data.remote_host, '212.74.15.68', msg = 'Line 1 remote_host')
        self.assertEqual(data.remote_logname, '-', msg = 'Line 1 remote_logname')
        self.assertEqual(data.remote_user, '-', msg = 'Line 1 remote_user')
        self.assertEqual(data.time, '[23/Jan/2004:11:36:20 +0000]', msg = 'Line 1 time')
        self.assertEqual(
            data.first_line,
            'GET /images/previous.png HTTP/1.1',
            msg = 'Line 1 first_line'
            )
        self.assertEqual(data.last_status, '200', msg = 'Line 1 last_status')
        self.assertEqual(data.response_bytes_clf, '2607', msg = 'Line 1 response_bytes_clf')
        self.assertEqual(
            data.header_Referer,
            'http://peterhi.dyndns.org/bandwidth/index.html',
            msg = 'Line 1 %{Referer}i'
            )
        self.assertEqual(
            data.header_User_Agent,
            'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.2) Gecko/20021202',
            msg = 'Line 1 %{User-Agent}i'
            )


    def testline2(self):
        data = self.p.parse(self.line2)
        self.assertEqual(data.remote_host, '212.74.15.68', msg = 'Line 2 remote_host')
        self.assertEqual(data.remote_logname, '-', msg = 'Line 2 remote_logname')
        self.assertEqual(data.remote_user, '-', msg = 'Line 2 remote_user')
        self.assertEqual(
            data.time,
            '[23/Jan/2004:11:36:20 +0000]',
            msg = 'Line 2 time'
            )
        self.assertEqual(
            data.first_line,
            r'GET /images/previous.png=\" HTTP/1.1',
            msg = 'Line 2 first_line'
            )
        self.assertEqual(data.last_status, '200', msg = 'Line 2 last_status')
        self.assertEqual(data.response_bytes_clf, '2607', msg = 'Line 2 response_bytes_clf')
        self.assertEqual(
            data.header_Referer,
            'http://peterhi.dyndns.org/bandwidth/index.html',
            msg = 'Line 2 %{Referer}i'
            )
        self.assertEqual(
            data.header_User_Agent,
            'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.2) Gecko/20021202',
            msg = 'Line 2 %{User-Agent}i'
            )

    def testline3(self):
        data = self.p.parse(self.line3)
        self.assertEqual(data.remote_host, '4.224.234.46', msg = 'Line 3 remote_host')
        self.assertEqual(data.remote_logname, '-', msg = 'Line 3 remote_logname')
        self.assertEqual(data.remote_user, '-', msg = 'Line 3 remote_user')
        self.assertEqual(
            data.time,
            '[20/Jul/2004:13:18:55 -0700]',
            msg = 'Line 3 time'
            )
        self.assertEqual(
            data.first_line,
            r'GET /core/listing/pl_boat_detail.jsp?&units=Feet&checked_boats='\
            r'1176818&slim=broker&&hosturl=giffordmarine&&ywo=giffordmarine& '\
            r'HTTP/1.1',
            msg = 'Line 3 first_line'
            )
        self.assertEqual(data.last_status, '200', msg = 'Line 3 last_status')
        self.assertEqual(data.response_bytes_clf, '2888', msg = 'Line 3 response_bytes_clf')
        self.assertEqual(
            data.header_Referer,
            r'http://search.yahoo.com/bin/search?p=\"grady%20white%20306'\
            r'%20bimini\"',
            msg = 'Line 3 %{Referer}i'
            )
        self.assertEqual(
            data.header_User_Agent,
            '\\"Mozilla/4.0 (compatible; MSIE 6.0; Windows 98; YPC 3.0.3; '\
            'yplus 4.0.00d)\\"',
#                'Mozilla/4.0 (compatible; MSIE 6.0; Windows 98; YPC 3.0.3; '\
#                'yplus 4.0.00d)',
            msg = 'Line 3 %{User-Agent}i'
            )


    def testjunkline(self):
        self.assertRaises(ApacheLogParserError,self.p.parse,'foobar')

    def testhasquotesaltn(self):
        p = parser(r'%a \"%b\" %c')
        line = r'foo "xyz" bar'
        data = p.parse(line)
        self.assertEqual(data['%a'],'foo', '%a')
        self.assertEqual(data['%b'],'xyz', '%c')
        self.assertEqual(data['%c'],'bar', '%c')


if __name__ is '__main__':
    unittest.main()
