import unittest

from windows_tun import route_plan


class WindowsTunPlanTests(unittest.TestCase):
    def test_endpoint_bypass_is_first_and_tun_routes_are_last(self):
        routes = route_plan('203.0.113.20', '192.168.1.1', 12, 44, [])
        self.assertEqual(routes[0], {
            'destination': '203.0.113.20', 'mask': '255.255.255.255',
            'gateway': '192.168.1.1', 'interface': 12, 'kind': 'bypass'
        })
        self.assertEqual([r['kind'] for r in routes[-2:]], ['tun', 'tun'])
        self.assertEqual([r['destination'] for r in routes[-2:]], ['0.0.0.0', '128.0.0.0'])
        self.assertTrue(all(r['interface'] == 44 for r in routes[-2:]))

    def test_public_dns_is_bypassed_but_lan_dns_is_not_added(self):
        routes = route_plan('203.0.113.20', '192.168.1.1', 12, 44,
                            ['1.1.1.1', '8.8.8.8', '192.168.1.1', 'not-an-ip'])
        bypass_ips = {r['destination'] for r in routes if r['kind'] == 'bypass'}
        self.assertEqual(bypass_ips, {'203.0.113.20', '1.1.1.1', '8.8.8.8'})

    def test_duplicate_endpoint_and_dns_ips_are_deduplicated(self):
        routes = route_plan('1.1.1.1', '192.168.1.1', 12, 44, ['1.1.1.1', '1.1.1.1'])
        self.assertEqual(sum(r['destination'] == '1.1.1.1' for r in routes), 1)

    def test_ipv6_endpoint_is_rejected_explicitly(self):
        with self.assertRaises(ValueError):
            route_plan('2001:4860:4860::8888', '192.168.1.1', 12, 44, [])

    def test_invalid_interface_indexes_are_rejected(self):
        with self.assertRaises(ValueError):
            route_plan('8.8.8.8', '192.168.1.1', 0, 44, [])
        with self.assertRaises(ValueError):
            route_plan('8.8.8.8', '192.168.1.1', 12, 12, [])


if __name__ == '__main__':
    unittest.main()
