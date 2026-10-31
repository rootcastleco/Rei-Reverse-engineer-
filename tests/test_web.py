import json
import threading
import unittest
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import urlopen
from rei_rea.web import CatalogHandler


class WebTests(unittest.TestCase):
    def test_live_loopback_dashboard_and_json(self):
        server=ThreadingHTTPServer(('127.0.0.1',0),CatalogHandler)
        worker=threading.Thread(target=server.serve_forever,daemon=True)
        worker.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        base=f'http://127.0.0.1:{server.server_port}'
        with urlopen(base+'/') as response:
            html=response.read().decode()
            self.assertIn('REI/REA', html.replace('<span>','').replace('</span>',''))
            self.assertIn('default-src',response.headers['Content-Security-Policy'])
        with urlopen(base+'/api/tools') as response:
            tools=json.load(response)['tools']
            self.assertGreaterEqual(len(tools),120)
        with self.assertRaises(HTTPError) as e:
            urlopen(base+'/api/unknown')
        self.assertEqual(e.exception.code,404)


if __name__=='__main__': unittest.main()
