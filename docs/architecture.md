# System Architecture

## Data Flow
1. **Data Collection**: AWS CloudTrail + Azure Monitor logs
2. **Data Processing**: Python-based ETL pipeline
3. **ML Analysis**: Isolation Forest algorithm
4. **Threat Detection**: Rule-based + ML-based detection
5. **Alerting**: Real-time notifications

## Components
- **Data Ingestion Layer**: Collects security logs
- **Processing Layer**: Cleans and transforms data
- **ML Layer**: Anomaly detection algorithms
- **Output Layer**: Threat intelligence reports

## Security Features
- Encryption at rest and in transit
- IAM role-based access control
- Automated security monitoring
