import boto3
import pandas as pd
from datetime import datetime, timedelta
from typing import List, Dict, Any
import json
from azure.identity import ClientSecretCredential
from azure.mgmt.monitor import MonitorManagementClient
from azure.mgmt.security import SecurityCenter
import requests

class AWSCloudTrailConnector:
    def __init__(self, config):
        self.config = config
        self.client = boto3.client(
            'cloudtrail',
            aws_access_key_id=config.aws.access_key,
            aws_secret_access_key=config.aws.secret_key,
            region_name=config.aws.region
        )
        self.s3_client = boto3.client(
            's3',
            aws_access_key_id=config.aws.access_key,
            aws_secret_access_key=config.aws.secret_key,
            region_name=config.aws.region
        )
    
    def get_events(self, start_time: datetime, end_time: datetime) -> List[Dict[str, Any]]:
        """Fetch CloudTrail events for given time range"""
        try:
            response = self.client.lookup_events(
                StartTime=start_time,
                EndTime=end_time,
                MaxResults=50
            )
            return response.get('Events', [])
        except Exception as e:
            print(f"Error fetching CloudTrail events: {e}")
            return []
    
    def process_cloudtrail_logs(self) -> pd.DataFrame:
        """Process CloudTrail logs from S3 bucket"""
        events_data = []
        
        try:
            # List objects in CloudTrail S3 bucket
            objects = self.s3_client.list_objects_v2(
                Bucket=self.config.aws.cloudtrail_bucket,
                Prefix='AWSLogs/',
                MaxKeys=100
            )
            
            for obj in objects.get('Contents', [])[:5]:  # Limit for demo
                if obj['Key'].endswith('.json.gz'):
                    # Download and process log file
                    log_data = self.download_and_process_log(obj['Key'])
                    events_data.extend(log_data)
        
        except Exception as e:
            print(f"Error processing CloudTrail logs: {e}")
        
        return pd.DataFrame(events_data)
    
    def download_and_process_log(self, key: str) -> List[Dict[str, Any]]:
        """Download and process individual log file"""
        # Simplified implementation - in real scenario, handle gzip decompression
        return []

class AzureMonitorConnector:
    def __init__(self, config):
        self.config = config
        self.credentials = ClientSecretCredential(
            tenant_id=config.azure.tenant_id,
            client_id=config.azure.client_id,
            client_secret=config.azure.client_secret
        )
        self.monitor_client = MonitorManagementClient(
            self.credentials,
            config.azure.subscription_id
        )
        self.security_client = SecurityCenter(
            self.credentials,
            config.azure.subscription_id,
            "default"
        )
    
    def get_activity_logs(self, start_time: datetime, end_time: datetime) -> List[Dict[str, Any]]:
        """Fetch Azure activity logs"""
        try:
            filter_str = f"eventTimestamp ge {start_time.isoformat()} and eventTimestamp le {end_time.isoformat()}"
            logs = self.monitor_client.activity_logs.list(filter=filter_str)
            
            events = []
            for log in logs:
                events.append({
                    'timestamp': log.event_timestamp,
                    'operation_name': log.operation_name.localized_value,
                    'resource_group': log.resource_group_name,
                    'resource_type': log.resource_type.localized_value,
                    'caller': log.caller,
                    'status': log.status.localized_value,
                    'subscription_id': log.subscription_id
                })
            
            return events
        except Exception as e:
            print(f"Error fetching Azure activity logs: {e}")
            return []
    
    def get_security_alerts(self) -> List[Dict[str, Any]]:
        """Fetch security alerts from Azure Security Center"""
        try:
            alerts = self.security_client.alerts.list()
            alert_data = []
            
            for alert in alerts:
                alert_data.append({
                    'alert_id': alert.name,
                    'display_name': alert.display_name,
                    'severity': alert.severity,
                    'status': alert.status,
                    'time_generated': alert.time_generated_utc,
                    'description': alert.description
                })
            
            return alert_data
        except Exception as e:
            print(f"Error fetching security alerts: {e}")
            return []

class CloudDataProcessor:
    def __init__(self):
        self.processed_events = 0
    
    def normalize_events(self, aws_events: List[Dict], azure_events: List[Dict]) -> pd.DataFrame:
        """Normalize events from different cloud providers"""
        normalized_data = []
        
        # Process AWS events
        for event in aws_events:
            normalized_event = {
                'cloud_provider': 'aws',
                'timestamp': event.get('EventTime', datetime.utcnow()),
                'event_name': event.get('EventName', ''),
                'user_identity': event.get('Username', 'Unknown'),
                'source_ip': event.get('SourceIPAddress', ''),
                'user_agent': event.get('UserAgent', ''),
                'event_type': 'api_call',
                'resource_type': event.get('Resources', [{}])[0].get('ResourceType', '') if event.get('Resources') else '',
                'region': event.get('AWSRegion', ''),
                'error_code': event.get('ErrorCode', ''),
                'request_parameters': str(event.get('RequestParameters', {})),
                'response_elements': str(event.get('ResponseElements', {}))
            }
            normalized_data.append(normalized_event)
        
        # Process Azure events
        for event in azure_events:
            normalized_event = {
                'cloud_provider': 'azure',
                'timestamp': event.get('timestamp', datetime.utcnow()),
                'event_name': event.get('operation_name', ''),
                'user_identity': event.get('caller', 'Unknown'),
                'source_ip': 'Unknown',  # Azure logs might not always have source IP
                'user_agent': '',
                'event_type': 'activity_log',
                'resource_type': event.get('resource_type', ''),
                'region': '',
                'error_code': '',
                'request_parameters': '',
                'response_elements': event.get('status', '')
            }
            normalized_data.append(normalized_event)
        
        self.processed_events += len(normalized_data)
        return pd.DataFrame(normalized_data)
    
    def extract_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Extract features for ML model"""
        if df.empty:
            return df
        
        # Time-based features
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df['hour'] = df['timestamp'].dt.hour
        df['day_of_week'] = df['timestamp'].dt.dayofweek
        df['is_weekend'] = df['day_of_week'].isin([5, 6]).astype(int)
        
        # User behavior features
        user_activity = df['user_identity'].value_counts()
        df['user_activity_frequency'] = df['user_identity'].map(user_activity)
        
        # Event type features
        event_frequency = df['event_name'].value_counts()
        df['event_frequency'] = df['event_name'].map(event_frequency)
        
        # Resource access patterns
        resource_access = df['resource_type'].value_counts()
        df['resource_access_frequency'] = df['resource_type'].map(resource_access)
        
        # Geographic features (simplified)
        df['is_usual_region'] = df.apply(
            lambda x: 1 if x['cloud_provider'] == 'aws' and x['region'] == 'us-east-1' else 0, 
            axis=1
        )
        
        # Error patterns
        df['has_error'] = df['error_code'].notna().astype(int)
        
        return df
