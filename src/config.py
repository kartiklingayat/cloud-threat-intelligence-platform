import os
import yaml
from dataclasses import dataclass
from typing import Dict, Any

@dataclass
class AWSConfig:
    access_key: str
    secret_key: str
    region: str
    cloudtrail_bucket: str

@dataclass
class AzureConfig:
    tenant_id: str
    client_id: str
    client_secret: str
    subscription_id: str

@dataclass
class MLConfig:
    model_path: str
    contamination: float
    n_estimators: int
    random_state: int

class Config:
    def __init__(self, config_path: str = "config.yaml"):
        self.config_path = config_path
        self.load_config()
    
    def load_config(self):
        if os.path.exists(self.config_path):
            with open(self.config_path, 'r') as file:
                config_data = yaml.safe_load(file)
        else:
            config_data = self.get_default_config()
        
        self.aws = AWSConfig(**config_data['aws'])
        self.azure = AzureConfig(**config_data['azure'])
        self.ml = MLConfig(**config_data['ml'])
        self.general = config_data['general']
    
    def get_default_config(self) -> Dict[str, Any]:
        return {
            'aws': {
                'access_key': os.getenv('AWS_ACCESS_KEY_ID', ''),
                'secret_key': os.getenv('AWS_SECRET_ACCESS_KEY', ''),
                'region': os.getenv('AWS_REGION', 'us-east-1'),
                'cloudtrail_bucket': os.getenv('CLOUDTRAIL_BUCKET', '')
            },
            'azure': {
                'tenant_id': os.getenv('AZURE_TENANT_ID', ''),
                'client_id': os.getenv('AZURE_CLIENT_ID', ''),
                'client_secret': os.getenv('AZURE_CLIENT_SECRET', ''),
                'subscription_id': os.getenv('AZURE_SUBSCRIPTION_ID', '')
            },
            'ml': {
                'model_path': 'models/anomaly_detector.joblib',
                'contamination': 0.1,
                'n_estimators': 100,
                'random_state': 42
            },
            'general': {
                'batch_size': 1000,
                'processing_interval': 300,
                'confidence_threshold': 0.85
            }
        }
