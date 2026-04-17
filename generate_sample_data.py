"""
Generate sample CloudTrail events for testing and training.
Creates 10,000 synthetic events with realistic patterns.
"""
import random
from datetime import datetime, timedelta
import json
from database import init_db, get_session, RawLog

# Sample data pools
USERS = ['alice', 'bob', 'charlie', 'david', 'eve', 'frank', 'grace', 'admin', 'service-account']
ACTIONS = [
    'DescribeInstances', 'ListBuckets', 'GetObject', 'PutObject',
    'CreateUser', 'DeleteUser', 'AttachUserPolicy', 'CreateAccessKey',
    'RunInstances', 'TerminateInstances', 'CreateBucket', 'DeleteBucket',
    'AuthorizeSecurityGroupIngress', 'ModifyDBInstance', 'AssumeRole',
    'ConsoleLogin', 'GetUser', 'ListUsers', 'DescribeSecurityGroups'
]
REGIONS = ['us-east-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1', 'us-east-2']
RESOURCES = [
    'arn:aws:s3:::my-bucket',
    'arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0',
    'arn:aws:iam::123456789012:user/alice',
    'arn:aws:rds:us-east-1:123456789012:db:mydb',
    'arn:aws:ec2:us-east-1:123456789012:security-group/sg-12345678'
]
OUTCOMES = ['Success', 'Success', 'Success', 'Success', 'Failed']  # 80% success rate


def generate_ip():
    """Generate random IP address."""
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"


def generate_event(event_id: int, timestamp: datetime) -> dict:
    """Generate a single CloudTrail event."""
    user = random.choice(USERS)
    action = random.choice(ACTIONS)
    region = random.choice(REGIONS)
    resource = random.choice(RESOURCES)
    outcome = random.choice(OUTCOMES)
    ip = generate_ip()
    
    # Add some anomalous patterns
    is_anomaly = random.random() < 0.05  # 5% anomalies
    
    if is_anomaly:
        # Anomalous patterns
        if random.random() < 0.3:
            # Off-hours access
            timestamp = timestamp.replace(hour=random.randint(0, 5))
        
        if random.random() < 0.3:
            # High privilege action
            action = random.choice(['CreateUser', 'DeleteUser', 'AttachUserPolicy', 'CreateAccessKey'])
        
        if random.random() < 0.3:
            # Unusual region
            region = 'ap-northeast-1'
        
        if random.random() < 0.3:
            # Failed login attempts
            action = 'ConsoleLogin'
            outcome = 'Failed'
    
    event = {
        'EventId': f'event-{event_id:08d}',
        'EventName': action,
        'EventTime': timestamp.isoformat(),
        'Username': user,
        'Resources': [{'ResourceName': resource}],
        'CloudTrailEvent': json.dumps({
            'sourceIPAddress': ip,
            'awsRegion': region,
            'errorCode': 'AccessDenied' if outcome == 'Failed' else None
        })
    }
    
    return event


def main():
    """Generate and save sample data."""
    print("Initializing database...")
    init_db()
    
    print("Generating 10,000 sample CloudTrail events...")
    
    session = get_session()
    
    # Generate events over last 30 days
    end_time = datetime.now()
    start_time = end_time - timedelta(days=30)
    
    events = []
    for i in range(10000):
        # Random timestamp within range
        random_seconds = random.randint(0, int((end_time - start_time).total_seconds()))
        timestamp = start_time + timedelta(seconds=random_seconds)
        
        event = generate_event(i, timestamp)
        
        # Create RawLog entry
        ct_data = json.loads(event['CloudTrailEvent'])
        
        # Parse EventTime back to datetime
        event_time = datetime.fromisoformat(event['EventTime'])
        
        raw_log = RawLog(
            event_id=event['EventId'],
            user=event['Username'],
            timestamp=event_time,
            ip=ct_data['sourceIPAddress'],
            action=event['EventName'],
            resource=event['Resources'][0]['ResourceName'],
            region=ct_data['awsRegion'],
            outcome='Failed' if ct_data.get('errorCode') else 'Success',
            raw_data=json.dumps(event)
        )
        
        session.add(raw_log)
        
        if (i + 1) % 1000 == 0:
            print(f"  Generated {i + 1} events...")
            session.commit()
    
    session.commit()
    session.close()
    
    print("✓ Successfully generated 10,000 sample events!")
    print("  Data saved to database")


if __name__ == '__main__':
    main()
