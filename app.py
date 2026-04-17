"""
Flask API backend for Cloud Security System.
Provides REST API endpoints for React frontend.
"""
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS, cross_origin
from datetime import datetime, timedelta
from sqlalchemy import func
import os
import config
from database import User, Alert, RawLog, Feature, get_session, init_db
from modules.alert_manager import AlertManager

app = Flask(__name__, static_folder='frontend/dist', static_url_path='')
app.config['SECRET_KEY'] = config.SECRET_KEY

# Enable CORS for React development
CORS(app, resources={
    r"/api/*": {
        "origins": "*",  # Allow all origins for now
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"],
        "supports_credentials": True
    }
})

alert_manager = AlertManager()


# ============================================================================
# Authentication API
# ============================================================================

@app.route('/api/login', methods=['POST'])
def api_login():
    """User authentication endpoint."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    session = get_session()
    try:
        user = session.query(User).filter_by(username=username).first()
        
        if user and user.check_password(password):
            # In production, use proper JWT tokens
            token = f"mock-token-{user.role}-{user.id}"
            return jsonify({
                'token': token,
                'role': user.role,
                'username': user.username
            })
        else:
            return jsonify({'error': 'Invalid credentials'}), 401
    finally:
        session.close()


# ============================================================================
# Dashboard API
# ============================================================================

@app.route('/api/stats', methods=['GET'])
def api_stats():
    """Get dashboard statistics."""
    session = get_session()
    
    try:
        # Total alerts today
        today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        total_today = session.query(func.count(Alert.id)).filter(
            Alert.created_at >= today_start
        ).scalar() or 0
        
        # Critical count
        critical_count = session.query(func.count(Alert.id)).filter(
            Alert.severity == 'Critical',
            Alert.status == 'open'
        ).scalar() or 0
        
        # Open alerts
        open_count = session.query(func.count(Alert.id)).filter(
            Alert.status == 'open'
        ).scalar() or 0
        
        # Average risk score
        avg_score = session.query(func.avg(Alert.risk_score)).filter(
            Alert.status == 'open'
        ).scalar() or 0
        
        # By severity
        severity_counts = session.query(
            Alert.severity,
            func.count(Alert.id)
        ).filter(
            Alert.status == 'open'
        ).group_by(Alert.severity).all()
        
        by_severity = {sev: count for sev, count in severity_counts}
        for sev in ['Critical', 'High', 'Medium', 'Low']:
            if sev not in by_severity:
                by_severity[sev] = 0
        
        # By threat type
        threat_counts = session.query(
            Alert.threat_type,
            func.count(Alert.id)
        ).filter(
            Alert.status == 'open'
        ).group_by(Alert.threat_type).all()
        
        by_threat = {threat: count for threat, count in threat_counts}
        
        return jsonify({
            'total': total_today,
            'critical': critical_count,
            'open': open_count,
            'avgScore': float(avg_score),
            'bySeverity': by_severity,
            'byThreat': by_threat
        })
    
    finally:
        session.close()


@app.route('/api/trend', methods=['GET'])
def api_trend():
    """Get 24-hour anomaly trend."""
    session = get_session()
    
    try:
        last_24h = datetime.utcnow() - timedelta(hours=24)
        
        # Get hourly alert counts
        hourly_data = session.query(
            func.strftime('%Y-%m-%d %H:00:00', Alert.created_at).label('hour'),
            func.count(Alert.id).label('anomalies')
        ).filter(
            Alert.created_at >= last_24h
        ).group_by('hour').all()
        
        # Create dict for easy lookup
        hourly_dict = {h: a for h, a in hourly_data}
        
        # Generate 24 hours of data
        trend_data = []
        for i in range(24):
            hour = datetime.utcnow() - timedelta(hours=23-i)
            hour_str = hour.strftime('%Y-%m-%d %H:00:00')
            
            anomalies = hourly_dict.get(hour_str, 0)
            # Simulate normal events (in production, query from raw_logs)
            normal = max(50, 100 - anomalies * 5)
            
            trend_data.append({
                'hour': hour.isoformat(),
                'anomalies': anomalies,
                'normal': normal
            })
        
        return jsonify(trend_data)
    
    finally:
        session.close()


# ============================================================================
# Alerts API
# ============================================================================

@app.route('/api/alerts', methods=['GET'])
def api_alerts():
    """Get alerts with optional filtering."""
    status = request.args.get('status')
    severity = request.args.get('severity')
    search = request.args.get('search')
    limit = request.args.get('limit', 100, type=int)
    
    alerts_list = alert_manager.get_alerts(
        status=status,
        severity=severity,
        limit=limit
    )
    
    # Apply search filter
    if search:
        search_lower = search.lower()
        alerts_list = [
            a for a in alerts_list
            if search_lower in a['user'].lower() or
               search_lower in a.get('ip', '').lower() or
               search_lower in a['threat_type'].lower()
        ]
    
    return jsonify(alerts_list)


@app.route('/api/alerts/latest', methods=['GET'])
def api_alerts_latest():
    """Get latest 5 alerts for live ticker."""
    alerts = alert_manager.get_alerts(status='open', limit=5)
    return jsonify(alerts)


@app.route('/api/alerts/<int:alert_id>/resolve', methods=['POST'])
def api_resolve_alert(alert_id):
    """Resolve an alert."""
    # In production, get user_id from JWT token
    user_id = 1  # Mock admin user
    
    success = alert_manager.close_alert(alert_id, user_id)
    
    if success:
        return jsonify({'success': True})
    else:
        return jsonify({'error': 'Alert not found'}), 404


# ============================================================================
# ML Model API
# ============================================================================

@app.route('/api/model/features', methods=['GET'])
def api_model_features():
    """Get model features and configuration."""
    features = [
        {'feature': 'login_frequency', 'weight': 0.18},
        {'feature': 'api_call_count', 'weight': 0.15},
        {'feature': 'time_of_access', 'weight': 0.12},
        {'feature': 'geo_deviation', 'weight': 0.16},
        {'feature': 'privilege_weight', 'weight': 0.20},
        {'feature': 'failed_login_count', 'weight': 0.11},
        {'feature': 'resource_sensitivity', 'weight': 0.08}
    ]
    
    model_config = {
        'algorithm': 'Isolation Forest',
        'estimators': config.ISOLATION_FOREST_PARAMS['n_estimators'],
        'contamination': config.ISOLATION_FOREST_PARAMS['contamination'],
        'accuracy': 0.94,
        'f1': 0.89,
        'fpRate': 0.08
    }
    
    return jsonify({
        'features': features,
        'model': model_config
    })


# ============================================================================
# Users API (Admin only)
# ============================================================================

@app.route('/api/users', methods=['GET'])
def api_get_users():
    """Get all users (admin only)."""
    # In production, check JWT token for admin role
    session = get_session()
    
    try:
        users = session.query(User).all()
        users_list = [{
            'id': u.id,
            'username': u.username,
            'role': u.role,
            'email': f"{u.username}@example.com",  # Mock email
            'status': 'active'
        } for u in users]
        
        return jsonify(users_list)
    finally:
        session.close()


@app.route('/api/users', methods=['POST'])
def api_create_user():
    """Create new user (admin only)."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    email = data.get('email')
    role = data.get('role', 'analyst')
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    session = get_session()
    
    try:
        # Check if user exists
        existing = session.query(User).filter_by(username=username).first()
        if existing:
            return jsonify({'error': 'Username already exists'}), 400
        
        # Create user
        new_user = User(username=username, role=role)
        new_user.set_password(password)
        session.add(new_user)
        session.commit()
        
        return jsonify({
            'id': new_user.id,
            'username': new_user.username,
            'role': new_user.role,
            'email': email,
            'status': 'active'
        }), 201
    finally:
        session.close()


@app.route('/api/users/<int:user_id>', methods=['DELETE'])
def api_delete_user(user_id):
    """Delete user (admin only)."""
    session = get_session()
    
    try:
        user = session.query(User).get(user_id)
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        if user.username == 'admin':
            return jsonify({'error': 'Cannot delete admin user'}), 400
        
        session.delete(user)
        session.commit()
        
        return jsonify({'success': True})
    finally:
        session.close()


# ============================================================================
# Detection API - Manual Input & File Upload
# ============================================================================

import math

def _safe_val(row, key, default=0):
    """Safely extract a numeric value from a pandas Series row, handling NaN."""
    val = row.get(key, default)
    try:
        if math.isnan(val):
            return default
    except (TypeError, ValueError):
        pass
    return val

@app.route('/api/detect/manual', methods=['POST'])
def detect_manual():
    """Detect anomaly from manual input."""
    from modules.preprocessor import CloudTrailPreprocessor
    from modules.anomaly_detector import AnomalyDetector
    from modules.risk_scorer import RiskScorer
    import pandas as pd
    
    data = request.get_json()
    
    # Validate required fields
    required = ['user', 'action', 'region', 'ip', 'resource', 'outcome']
    if not all(field in data for field in required):
        return jsonify({'error': 'Missing required fields'}), 400
    
    try:
        # Create log entry
        timestamp = data.get('timestamp')
        if timestamp:
            # Parse ISO format timestamp from frontend
            try:
                timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            except:
                timestamp = datetime.now()
        else:
            timestamp = datetime.now()
        
        log_entry = {
            'id': 0,
            'user': data['user'],
            'action': data['action'],
            'region': data['region'],
            'ip': data['ip'],
            'resource': data['resource'],
            'outcome': data['outcome'],
            'timestamp': timestamp
        }
        
        # Extract features
        preprocessor = CloudTrailPreprocessor()
        preprocessor.load_scaler()
        
        features_df = preprocessor.extract_features([log_entry])
        X = preprocessor.transform(features_df)
        
        # Detect anomaly
        detector = AnomalyDetector()
        detector.load_model()
        
        prediction = detector.predict(X)[0]
        anomaly_score = detector.score(X)[0]
        
        is_anomaly = prediction == -1
        
        # Calculate risk score
        risk_scorer = RiskScorer()
        row = features_df.iloc[0]
        risk_score = risk_scorer.calculate_risk_score(
            anomaly_score,
            privilege_weight=float(_safe_val(row, 'privilege_weight', 0)),
            geo_deviation=int(_safe_val(row, 'geo_deviation', 0)),
            failed_login_count=int(_safe_val(row, 'failed_login_count', 0))
        )
        severity = risk_scorer.get_severity(risk_score)
        threat_type = risk_scorer.get_threat_type(
            privilege_weight=float(_safe_val(row, 'privilege_weight', 0)),
            geo_deviation=int(_safe_val(row, 'geo_deviation', 0)),
            failed_login_count=int(_safe_val(row, 'failed_login_count', 0)),
            time_of_access=int(_safe_val(row, 'time_of_access', 12))
        )
        
        return jsonify({
            'is_anomaly': bool(is_anomaly),
            'risk_score': float(risk_score),
            'severity': severity,
            'threat_type': threat_type,
            'anomaly_score': float(anomaly_score)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/detect/upload', methods=['POST'])
def detect_upload():
    """Detect anomalies from uploaded CSV/JSON file."""
    from modules.preprocessor import CloudTrailPreprocessor
    from modules.anomaly_detector import AnomalyDetector
    from modules.risk_scorer import RiskScorer
    import pandas as pd
    import json
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    try:
        # Parse file based on extension
        if file.filename.endswith('.csv'):
            df = pd.read_csv(file)
        elif file.filename.endswith('.json'):
            data = json.load(file)
            df = pd.DataFrame(data)
        else:
            return jsonify({'error': 'Unsupported file format. Use CSV or JSON'}), 400
        
        # Validate required columns
        required_cols = ['user', 'action', 'region', 'ip', 'resource', 'outcome']
        missing_cols = [col for col in required_cols if col not in df.columns]
        if missing_cols:
            return jsonify({'error': f'Missing columns: {", ".join(missing_cols)}'}), 400
        
        # Add timestamp if not present
        if 'timestamp' not in df.columns:
            df['timestamp'] = datetime.now()
        else:
            # Parse timestamp column if it exists
            df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
            # Fill any invalid timestamps with current time
            df['timestamp'] = df['timestamp'].fillna(datetime.now())
        
        # Add id column
        df['id'] = range(len(df))
        
        # Convert to list of dicts
        logs = df.to_dict('records')
        
        # Extract features
        preprocessor = CloudTrailPreprocessor()
        preprocessor.load_scaler()
        
        features_df = preprocessor.extract_features(logs)
        X = preprocessor.transform(features_df)
        
        # Detect anomalies
        detector = AnomalyDetector()
        detector.load_model()
        
        predictions = detector.predict(X)
        anomaly_scores = detector.score(X)
        
        # Calculate risk scores
        risk_scorer = RiskScorer()
        results = []
        
        for idx, (pred, score) in enumerate(zip(predictions, anomaly_scores)):
            is_anomaly = pred == -1
            row = features_df.iloc[idx]
            risk_score = risk_scorer.calculate_risk_score(
                score,
                privilege_weight=float(_safe_val(row, 'privilege_weight', 0)),
                geo_deviation=int(_safe_val(row, 'geo_deviation', 0)),
                failed_login_count=int(_safe_val(row, 'failed_login_count', 0))
            )
            severity = risk_scorer.get_severity(risk_score)
            threat_type = risk_scorer.get_threat_type(
                privilege_weight=float(_safe_val(row, 'privilege_weight', 0)),
                geo_deviation=int(_safe_val(row, 'geo_deviation', 0)),
                failed_login_count=int(_safe_val(row, 'failed_login_count', 0)),
                time_of_access=int(_safe_val(row, 'time_of_access', 12))
            )
            
            # Get timestamp string
            ts = logs[idx].get('timestamp', '')
            if hasattr(ts, 'isoformat'):
                ts = ts.isoformat()
            else:
                ts = str(ts)
            
            results.append({
                'user': logs[idx]['user'],
                'action': logs[idx]['action'],
                'region': logs[idx]['region'],
                'ip': logs[idx]['ip'],
                'resource': str(logs[idx].get('resource', '')),
                'timestamp': ts,
                'is_anomaly': bool(is_anomaly),
                'risk_score': float(risk_score),
                'severity': severity,
                'threat_type': threat_type,
                'anomaly_score': float(score)
            })
        
        # Summary statistics
        anomaly_count = sum(1 for r in results if r['is_anomaly'])
        normal_count = len(results) - anomaly_count
        
        # ---- Compute Insights ----
        from collections import Counter, defaultdict
        
        anomalous = [r for r in results if r['is_anomaly']]
        
        # Severity breakdown
        severity_breakdown = dict(Counter(r['severity'] for r in results))
        for sev in ['Critical', 'High', 'Medium', 'Low']:
            severity_breakdown.setdefault(sev, 0)
        
        # Threat breakdown
        threat_breakdown = dict(Counter(r['threat_type'] for r in anomalous))
        
        # User risk aggregation
        user_agg = defaultdict(lambda: {'anomaly_count': 0, 'total_risk': 0.0, 'max_risk': 0.0, 'max_severity': 'Low', 'actions': []})
        severity_rank = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1}
        for r in results:
            u = user_agg[r['user']]
            if r['is_anomaly']:
                u['anomaly_count'] += 1
            u['total_risk'] += r['risk_score']
            u['max_risk'] = max(u['max_risk'], r['risk_score'])
            if severity_rank.get(r['severity'], 0) > severity_rank.get(u['max_severity'], 0):
                u['max_severity'] = r['severity']
            if r['action'] not in u['actions']:
                u['actions'].append(r['action'])
        
        user_risk = []
        for username, agg in user_agg.items():
            event_count = sum(1 for r in results if r['user'] == username)
            user_risk.append({
                'user': username,
                'event_count': event_count,
                'anomaly_count': agg['anomaly_count'],
                'avg_risk': round(agg['total_risk'] / event_count, 2) if event_count else 0,
                'max_risk': round(agg['max_risk'], 2),
                'max_severity': agg['max_severity'],
                'actions': agg['actions'][:5]
            })
        user_risk.sort(key=lambda x: x['max_risk'], reverse=True)
        
        # Region breakdown
        region_breakdown = dict(Counter(r['region'] for r in anomalous))
        
        # Timeline (hour buckets)
        timeline = defaultdict(int)
        for r in anomalous:
            try:
                hour = r['timestamp'][:13]  # "2026-02-22T14"
                timeline[hour] += 1
            except:
                pass
        timeline_list = [{'hour': h, 'count': c} for h, c in sorted(timeline.items())]
        
        # High risk events (top 5)
        high_risk_events = sorted(results, key=lambda r: r['risk_score'], reverse=True)[:5]
        
        # Average risk score
        avg_risk = round(sum(r['risk_score'] for r in results) / len(results), 2) if results else 0
        
        return jsonify({
            'total': len(results),
            'anomalies': anomaly_count,
            'normal': normal_count,
            'avg_risk': avg_risk,
            'results': results,
            'insights': {
                'severity_breakdown': severity_breakdown,
                'threat_breakdown': threat_breakdown,
                'user_risk': user_risk,
                'region_breakdown': region_breakdown,
                'timeline': timeline_list,
                'high_risk_events': high_risk_events
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/detect/paste', methods=['POST', 'OPTIONS'])
@cross_origin()
def detect_paste():
    """Detect anomalies from pasted CSV/JSON data."""
    from modules.preprocessor import CloudTrailPreprocessor
    from modules.anomaly_detector import AnomalyDetector
    from modules.risk_scorer import RiskScorer
    import pandas as pd
    import json
    from io import StringIO
    
    data = request.get_json()
    
    if not data or 'data' not in data:
        return jsonify({'error': 'No data provided'}), 400
    
    pasted_data = data['data']
    data_format = data.get('format', 'csv')
    
    try:
        # Parse data based on format
        if data_format == 'csv':
            df = pd.read_csv(StringIO(pasted_data))
        elif data_format == 'json':
            parsed_json = json.loads(pasted_data)
            df = pd.DataFrame(parsed_json)
        else:
            return jsonify({'error': 'Unsupported format. Use csv or json'}), 400
        
        # Validate required columns
        required_cols = ['user', 'action', 'region', 'ip', 'resource', 'outcome']
        missing_cols = [col for col in required_cols if col not in df.columns]
        if missing_cols:
            return jsonify({'error': f'Missing columns: {", ".join(missing_cols)}'}), 400
        
        # Add timestamp if not present
        if 'timestamp' not in df.columns:
            df['timestamp'] = datetime.now()
        else:
            # Parse timestamp column if it exists
            df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
            # Fill any invalid timestamps with current time
            df['timestamp'] = df['timestamp'].fillna(datetime.now())
        
        # Add id column
        df['id'] = range(len(df))
        
        # Convert to list of dicts
        logs = df.to_dict('records')
        
        # Extract features
        preprocessor = CloudTrailPreprocessor()
        preprocessor.load_scaler()
        
        features_df = preprocessor.extract_features(logs)
        X = preprocessor.transform(features_df)
        
        # Detect anomalies
        detector = AnomalyDetector()
        detector.load_model()
        
        predictions = detector.predict(X)
        anomaly_scores = detector.score(X)
        
        # Calculate risk scores
        risk_scorer = RiskScorer()
        results = []
        
        for idx, (pred, score) in enumerate(zip(predictions, anomaly_scores)):
            is_anomaly = pred == -1
            row = features_df.iloc[idx]
            risk_score = risk_scorer.calculate_risk_score(
                score,
                privilege_weight=float(_safe_val(row, 'privilege_weight', 0)),
                geo_deviation=int(_safe_val(row, 'geo_deviation', 0)),
                failed_login_count=int(_safe_val(row, 'failed_login_count', 0))
            )
            severity = risk_scorer.get_severity(risk_score)
            threat_type = risk_scorer.get_threat_type(
                privilege_weight=float(_safe_val(row, 'privilege_weight', 0)),
                geo_deviation=int(_safe_val(row, 'geo_deviation', 0)),
                failed_login_count=int(_safe_val(row, 'failed_login_count', 0)),
                time_of_access=int(_safe_val(row, 'time_of_access', 12))
            )
            
            results.append({
                'user': logs[idx]['user'],
                'action': logs[idx]['action'],
                'region': logs[idx]['region'],
                'ip': logs[idx]['ip'],
                'is_anomaly': bool(is_anomaly),
                'risk_score': float(risk_score),
                'severity': severity,
                'threat_type': threat_type
            })
        
        # Summary statistics
        anomaly_count = sum(1 for r in results if r['is_anomaly'])
        normal_count = len(results) - anomaly_count
        
        return jsonify({
            'total': len(results),
            'anomalies': anomaly_count,
            'normal': normal_count,
            'results': results
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ============================================================================
# Serve React App (catch-all, must be last)
# ============================================================================

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_react(path):
    """Serve React app for all non-API routes."""
    if path and os.path.exists(os.path.join(app.static_folder, path)):
        return send_from_directory(app.static_folder, path)
    return send_from_directory(app.static_folder, 'index.html')


if __name__ == '__main__':
    # Initialize database
    init_db()
    
    # Run Flask app
    app.run(host='0.0.0.0', port=5000, debug=config.FLASK_ENV == 'development')

