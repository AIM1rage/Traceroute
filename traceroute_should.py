import unittest
from traceroute import *


class TracerouteTest(unittest.TestCase):
    def test_habrahabr_windows(self):
        tracert = Traceroute('habrahabr.ru')
        data = list(tracert.get_trace_data())
        command = ['tracert', '-d', '-h', '30', 'habrahabr.ru']
        output = subprocess.check_output(command).decode('cp1251')
        for _, pings in data:
            for ping, src in pings:
                self.assertTrue(src is None or src in output)


if __name__ == '__main__':
    unittest.main()
