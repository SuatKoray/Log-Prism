import unittest
import os
import sys


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.detector import Detector
from src.log_reader import LogReader

class TestLogPrism(unittest.TestCase):
    
    def setUp(self):
        """Her testten önce çalışır. Geçici ortam hazırlar."""
        self.test_log_file = "test_log.txt"
        with open(self.test_log_file, "w") as f:
            f.write('192.168.1.1 - - [10/Oct/2023] "GET /index.php?id=1 UNION SELECT password FROM users" 200 -\n')
            f.write('192.168.1.1 - - [10/Oct/2023] "GET /style.css" 200 -\n') # Temiz satır

        # Config yolunu tam belirtmemiz gerekebilir, şimdilik mock 
        self.detector = Detector("config/signatures.json")

    def tearDown(self):
        """Her testten sonra çalışır. Ortalığı temizler."""
        if os.path.exists(self.test_log_file):
            os.remove(self.test_log_file)

    def test_sql_injection_detection(self):
        """SQL Injection tespiti çalışıyor mu?"""
        log_line = 'GET /index.php?id=1 UNION SELECT 1,2,3'
        result = self.detector.scan_line(log_line)
        self.assertIsNotNone(result) 
        self.assertEqual(result['alert_type'], 'SQL Injection')

    def test_clean_line(self):
        """Temiz log satırında alarm vermemeli."""
        log_line = 'GET /home.html HTTP/1.1'
        result = self.detector.scan_line(log_line)
        self.assertIsNone(result) 

    def test_reader_file_exists(self):
        """LogReader dosyayı gerçekten okuyor mu?"""
        reader = LogReader(self.test_log_file)
        lines = list(reader.read_logs())
        self.assertEqual(len(lines), 2) 

if __name__ == '__main__':
    unittest.main()