import unittest
from traceroute import *


class TracerouteTest(unittest.TestCase):
    def test_habrahabr_windows(self):
        tracert = Traceroute('habrahabr.ru')
        data = list(tracert.get_trace_data())
        command = ['tracert', '-d', '-h', '30', 'habrahabr.ru']
        output = subprocess.check_output(command).decode('cp1251')
        for *_, src in data:
            if src is not None:
                self.assertTrue(src in output)


if __name__ == '__main__':
    unittest.main()
