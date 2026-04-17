"""
Train the anomaly detection model on CloudTrail data.
"""
import numpy as np
from database import get_session, RawLog, Feature
from modules.preprocessor import CloudTrailPreprocessor
from modules.anomaly_detector import AnomalyDetector
from modules.alert_manager import AlertManager
import config


def main():
    """Train model and generate alerts."""
    print("="*60)
    print("CLOUD SECURITY ANOMALY DETECTION - TRAINING")
    print("="*60)
    
    # Load data from database
    print("\n1. Loading data from database...")
    session = get_session()
    
    logs = session.query(RawLog).all()
    print(f"   Loaded {len(logs)} log entries")
    
    if len(logs) == 0:
        print("   ERROR: No logs found. Run generate_sample_data.py first!")
        return
    
    # Convert to dict format
    logs_dict = []
    for log in logs:
        logs_dict.append({
            'id': log.id,
            'event_id': log.event_id,
            'user': log.user,
            'timestamp': log.timestamp,
            'ip': log.ip,
            'action': log.action,
            'resource': log.resource,
            'region': log.region,
            'outcome': log.outcome
        })
    
    # Feature engineering
    print("\n2. Engineering features...")
    preprocessor = CloudTrailPreprocessor()
    features_df = preprocessor.extract_features(logs_dict)
    print(f"   Extracted {len(features_df.columns)} features")
    print(f"   Features: {list(features_df.columns)}")
    
    # Save features to database
    print("\n3. Saving features to database...")
    feature_cols = [
        'login_frequency', 'api_call_count', 'time_of_access',
        'geo_deviation', 'privilege_weight', 'failed_login_count',
        'resource_sensitivity'
    ]
    
    for idx, row in features_df.iterrows():
        log_id = logs_dict[idx]['id']
        
        # Check if feature already exists
        existing = session.query(Feature).filter_by(log_id=log_id).first()
        if existing:
            continue
        
        feature = Feature(
            log_id=log_id,
            login_frequency=row['login_frequency'],
            api_call_count=row['api_call_count'],
            time_of_access=row['time_of_access'],
            geo_deviation=row['geo_deviation'],
            privilege_weight=row['privilege_weight'],
            failed_login_count=row['failed_login_count'],
            resource_sensitivity=row['resource_sensitivity']
        )
        session.add(feature)
    
    session.commit()
    print("   Features saved!")
    
    # Normalize features
    print("\n4. Normalizing features...")
    X = preprocessor.fit_transform(features_df)
    print(f"   Normalized shape: {X.shape}")
    
    # Save scaler
    preprocessor.save_scaler()
    
    # Split data (80/20)
    split_idx = int(0.8 * len(X))
    X_train = X[:split_idx]
    X_test = X[split_idx:]
    
    print(f"   Training set: {X_train.shape[0]} samples")
    print(f"   Test set: {X_test.shape[0]} samples")
    
    # Train model
    print("\n5. Training Isolation Forest model...")
    detector = AnomalyDetector()
    detector.train(X_train)
    
    # Evaluate on test set
    print("\n6. Evaluating model...")
    # Generate pseudo-labels for evaluation (predictions as ground truth)
    y_test_pred = detector.predict(X_test)
    detector.evaluate(X_test, y_test_pred)
    
    # Detect anomalies on full dataset
    print("\n7. Detecting anomalies...")
    predictions = detector.predict(X)
    anomaly_scores = detector.score(X)
    
    anomaly_count = np.sum(predictions == -1)
    print(f"   Found {anomaly_count} anomalies ({anomaly_count/len(predictions)*100:.2f}%)")
    
    # Generate alerts for anomalies
    print("\n8. Generating alerts...")
    alert_manager = AlertManager()
    
    anomaly_indices = np.where(predictions == -1)[0]
    anomaly_log_ids = [logs_dict[i]['id'] for i in anomaly_indices]
    anomaly_scores_filtered = anomaly_scores[anomaly_indices]
    anomaly_features = features_df.iloc[anomaly_indices]
    
    alerts_created = alert_manager.create_alerts(
        anomaly_log_ids,
        anomaly_scores_filtered,
        anomaly_features
    )
    
    print(f"   Created {alerts_created} alerts")
    
    # Summary statistics
    print("\n" + "="*60)
    print("TRAINING COMPLETE!")
    print("="*60)
    print(f"Total logs processed: {len(logs)}")
    print(f"Anomalies detected: {anomaly_count}")
    print(f"Alerts created: {alerts_created}")
    print(f"Model saved to: {config.MODEL_PATH}")
    print(f"Scaler saved to: {config.SCALER_PATH}")
    print("\nYou can now run the Flask dashboard:")
    print("  flask run --host=0.0.0.0 --port=5000")
    print("="*60)
    
    session.close()


if __name__ == '__main__':
    main()
