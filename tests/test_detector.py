import unittest
import pandas as pd
import numpy as np
from datetime import datetime
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from src.anomaly_detector import BehavioralAnomalyDetector
from src.threat_analyzer import ThreatAnalyzer
from src.config import Config

class TestAnomalyDetector(unittest.TestCase):
    def setUp(self):
        self.config = Config()
        self.detector = BehavioralAnomalyDetector(self.config)
        
        # Create sample data
        self.sample_data = pd.DataFrame({
            'timestamp': [datetime.now()] * 10,
            'event_name': ['DescribeInstances'] * 8 + ['CreateUser'] * 2,
            'user_identity': ['user1'] * 5 + ['user2'] * 5,
            'source_ip': ['192.168.1.1'] * 10,
            'resource_type': ['ec2'] * 10,
            'hour': [9] * 8 + [3] * 2,  # Some unusual hours
            'day_of_week': [1] * 10,
            'user_activity_frequency': [5] * 5 + [5] * 5,
            'event_frequency': [8] * 8 + [2] * 2
        })
    
    def test_training(self):
        """Test model training"""
        results = self.detector.train(self.sample_data)
        self.assertIn('accuracy', results)
        self.assertTrue(self.detector.is_trained)
    
    def test_detection(self):
        """Test anomaly detection"""
        self.detector.train(self.sample_data)
        anomalies, stats = self.detector.detect(self.sample_data)
        
        self.assertIn('anomalies_detected', stats)
        self.assertIsInstance(anomalies, pd.DataFrame)

class TestThreatAnalyzer(unittest.TestCase):
    def setUp(self):
        self.analyzer = ThreatAnalyzer()
        
        self.sample_events = pd.DataFrame({
            'event_name': ['CreateUser', 'DescribeInstances'],
            'user_identity': ['admin', 'user1'],
            'source_ip': ['192.168.1.100', '192.168.1.2'],  # First IP is malicious
            'user_agent': ['nmap', 'Mozilla/5.0'],
            'timestamp': [datetime.now()] * 2
        })
    
    def test_threat_analysis(self):
        """Test threat analysis"""
        results = self.analyzer.analyze_events(self.sample_events)
        self.assertIn('threats_detected', results)
        self.assertGreaterEqual(results['threats_detected'], 1)  # Should detect malicious IP
    
    def test_report_generation(self):
        """Test threat report generation"""
        analysis = self.analyzer.analyze_events(self.sample_events)
        report = self.analyzer.generate_threat_report(analysis)
        self.assertIsInstance(report, str)
        self.assertIn('THREAT INTELLIGENCE REPORT', report)

if __name__ == '__main__':
    unittest.main()
