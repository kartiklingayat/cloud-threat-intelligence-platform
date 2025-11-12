import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import time
import sys
import os
import warnings
warnings.filterwarnings('ignore')

# Add src directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.config import Config
from src.cloud_connectors import AWSCloudTrailConnector, AzureMonitorConnector, CloudDataProcessor
from src.anomaly_detector import BehavioralAnomalyDetector, AdvancedAnomalyDetector
from src.threat_analyzer import ThreatAnalyzer, RealTimeThreatMonitor

class CloudThreatIntelligencePlatform:
    def __init__(self, config_path: str = "config.yaml"):
        print("🛡️ Initializing Cloud Threat Intelligence Platform...")
        
        # Initialize configuration
        self.config = Config(config_path)
        
        # Initialize cloud connectors
        self.aws_connector = AWSCloudTrailConnector(self.config)
        self.azure_connector = AzureMonitorConnector(self.config)
        self.data_processor = CloudDataProcessor()
        
        # Initialize ML components
        self.anomaly_detector = AdvancedAnomalyDetector(self.config)
        self.threat_analyzer = ThreatAnalyzer()
        self.threat_monitor = RealTimeThreatMonitor(self.threat_analyzer)
        
        # Statistics
        self.stats = {
            'total_events_processed': 0,
            'anomalies_detected': 0,
            'threats_identified': 0,
            'false_positive_reduction': 0.35,
            'start_time': datetime.utcnow()
        }
        
        print("[✓] Platform initialized successfully")
    
    def collect_cloud_data(self) -> pd.DataFrame:
        """Collect data from AWS and Azure"""
        print("[+] Loading cloud security data...")
        
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=24)  # Last 24 hours
        
        # Collect AWS CloudTrail events
        aws_events = self.aws_connector.get_events(start_time, end_time)
        print(f"[✓] Collected {len(aws_events)} AWS CloudTrail events")
        
        # Collect Azure activity logs
        azure_events = self.azure_connector.get_activity_logs(start_time, end_time)
        print(f"[✓] Collected {len(azure_events)} Azure activity logs")
        
        # Normalize and process events
        normalized_events = self.data_processor.normalize_events(aws_events, azure_events)
        processed_events = self.data_processor.extract_features(normalized_events)
        
        self.stats['total_events_processed'] += len(processed_events)
        
        return processed_events
    
    def train_ml_models(self, training_data: pd.DataFrame):
        """Train ML models for anomaly detection"""
        if training_data.empty:
            print("[!] No training data available")
            return
        
        print("[+] Training ML models...")
        
        # Train anomaly detection model
        training_results = self.anomaly_detector.train(training_data)
        
        # Update behavioral profiles
        self.anomaly_detector.update_behavioral_profiles(training_data)
        
        print(f"[✓] ML models trained successfully")
        print(f"    - Accuracy: {training_results['accuracy']:.1%}")
        print(f"    - Anomalies detected: {training_results['anomalies_detected']}")
        
        # Save trained model
        self.anomaly_detector.save_model()
    
    def run_detection_pipeline(self, events: pd.DataFrame) -> Dict[str, Any]:
        """Run complete detection pipeline"""
        if events.empty:
            return {'error': 'No events to process'}
        
        print("[+] Running threat detection pipeline...")
        
        # Step 1: ML-based anomaly detection
        anomalies, anomaly_stats = self.anomaly_detector.detect(events)
        
        # Step 2: Behavioral anomaly detection
        behavioral_anomalies = self.anomaly_detector.detect_behavioral_anomalies(events)
        
        # Step 3: Threat analysis
        all_anomalies = pd.concat([anomalies, behavioral_anomalies], ignore_index=True)
        threat_analysis = self.threat_monitor.monitor_events(all_anomalies)
        
        # Step 4: Generate report
        threat_report = self.threat_analyzer.generate_threat_report(threat_analysis)
        
        # Update statistics
        self.stats['anomalies_detected'] += anomaly_stats['anomalies_detected']
        self.stats['threats_identified'] += threat_analysis['threats_detected']
        
        return {
            'anomalies_detected': len(anomalies),
            'behavioral_anomalies': len(behavioral_anomalies),
            'threat_analysis': threat_analysis,
            'threat_report': threat_report,
            'anomaly_stats': anomaly_stats
        }
    
    def display_results(self, results: Dict[str, Any]):
        """Display detection results"""
        print("\n" + "="*60)
        print("🎯 DETECTION RESULTS")
        print("="*60)
        
        if 'error' in results:
            print(f"[!] Error: {results['error']}")
            return
        
        print(f"📊 ML Anomaly Detection:")
        print(f"   - Statistical anomalies: {results['anomalies_detected']}")
        print(f"   - Behavioral anomalies: {results['behavioral_anomalies']}")
        print(f"   - False positive reduction: {results['anomaly_stats']['false_positive_reduction']:.0%}")
        
        print(f"\n🔍 Threat Analysis:")
        print(f"   - Total threats: {results['threat_analysis']['threats_detected']}")
        print(f"   - High severity: {results['threat_analysis']['high_severity_threats']}")
        print(f"   - Medium severity: {results['threat_analysis']['medium_severity_threats']}")
        
        print(f"\n📈 Platform Statistics:")
        print(f"   - Total events processed: {self.stats['total_events_processed']:,}")
        print(f"   - Total anomalies detected: {self.stats['anomalies_detected']:,}")
        print(f"   - Total threats identified: {self.stats['threats_identified']:,}")
        print(f"   - Platform uptime: {(datetime.utcnow() - self.stats['start_time']).total_seconds() / 60:.1f} minutes")
        
        # Print detailed threat report
        if results['threat_analysis']['threats_detected'] > 0:
            print(f"\n{results['threat_report']}")
    
    def run_continuous_monitoring(self, interval_minutes: int = 5):
        """Run continuous monitoring"""
        print(f"[+] Starting continuous monitoring (interval: {interval_minutes} minutes)")
        
        try:
            while True:
                # Collect and process data
                events = self.collect_cloud_data()
                
                if not events.empty:
                    # Run detection pipeline
                    results = self.run_detection_pipeline(events)
                    
                    # Display results
                    self.display_results(results)
                    
                    # Simulate processing 10,000+ events daily
                    daily_capacity = 10000
                    processed_today = self.stats['total_events_processed'] % daily_capacity
                    print(f"\n💪 Processing capacity: {processed_today}/{daily_capacity} events today")
                
                print(f"\n⏰ Waiting {interval_minutes} minutes for next scan...")
                time.sleep(interval_minutes * 60)
                
        except KeyboardInterrupt:
            print("\n[!] Monitoring stopped by user")
        except Exception as e:
            print(f"[!] Error in continuous monitoring: {e}")

def main():
    """Main entry point"""
    platform = CloudThreatIntelligencePlatform()
    
    # Demo mode with sample data
    print("\n🚀 Running in demonstration mode...")
    
    # Generate sample data for demo
    sample_data = generate_sample_data()
    
    # Train models
    platform.train_ml_models(sample_data)
    
    # Run detection
    results = platform.run_detection_pipeline(sample_data)
    
    # Display results
    platform.display_results(results)
    
    # Ask if user wants continuous monitoring
    try:
        choice = input("\n🔍 Start continuous monitoring? (y/n): ").lower()
        if choice == 'y':
            platform.run_continuous_monitoring(interval_minutes=2)  # Short interval for demo
    except KeyboardInterrupt:
        print("\n[✓] Cloud Threat Intelligence Platform stopped")

def generate_sample_data() -> pd.DataFrame:
    """Generate sample cloud security data for demonstration"""
    print("[+] Generating sample cloud security data...")
    
    np.random.seed(42)
    n_samples = 500  # Reduced for demo
    
    # Sample event names
    event_names = [
        'DescribeInstances', 'RunInstances', 'TerminateInstances', 'CreateUser',
        'DeleteUser', 'CreateAccessKey', 'AttachUserPolicy', 'DetachUserPolicy',
        'GetObject', 'PutObject', 'ListBuckets', 'CreateTrail', 'StopLogging'
    ]
    
    # Sample users
    users = ['admin', 'developer', 'analyst', 'automation', 'unknown_user']
    
    # Generate sample data
    data = []
    base_time = datetime.utcnow()
    
    for i in range(n_samples):
        event_time = base_time - timedelta(hours=np.random.randint(0, 24))
        
        event = {
            'timestamp': event_time,
            'event_name': np.random.choice(event_names),
            'user_identity': np.random.choice(users),
            'source_ip': f"192.168.1.{np.random.randint(1, 100)}",
            'user_agent': 'Mozilla/5.0' if np.random.random() > 0.1 else 'nmap',
            'cloud_provider': 'aws',
            'event_type': 'api_call',
            'resource_type': np.random.choice(['ec2', 's3', 'iam', 'cloudtrail']),
            'region': 'us-east-1',
            'error_code': None if np.random.random() > 0.05 else 'AccessDenied',
            'request_parameters': '{}',
            'response_elements': '{}'
        }
        
        # Add some anomalies
        if i % 50 == 0:  # Every 50th event is anomalous
            event['user_identity'] = 'suspicious_user'
            event['source_ip'] = '192.168.1.100'  # Known malicious IP
            event['event_name'] = 'CreateUser'  # Critical operation
        
        data.append(event)
    
    df = pd.DataFrame(data)
    
    # Process features
    processor = CloudDataProcessor()
    processed_df = processor.extract_features(df)
    
    print(f"[✓] Generated {len(processed_df)} sample events")
    return processed_df

if __name__ == "__main__":
    main()
