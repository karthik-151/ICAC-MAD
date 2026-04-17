# System Architecture — Cloud Security Anomaly Detection

> **ICAC-MDS** — Intelligent Cloud Activity Classifier using Machine Learning Detection System

---

## High-Level Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                        CLIENT BROWSER                              │
│                                                                    │
│   ┌──────────────────────────────────────────────────────────────┐  │
│   │              React Dashboard (Port 3000)                     │  │
│   │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐       │  │
│   │  │Dashboard │ │ Alerts   │ │ Detect   │ │ ML Model │       │  │
│   │  │          │ │          │ │ (Upload) │ │          │       │  │
│   │  └──────────┘ └──────────┘ └──────────┘ └──────────┘       │  │
│   └──────────────────────────┬───────────────────────────────────┘  │
│                              │ Axios (API calls)                   │
└──────────────────────────────┼─────────────────────────────────────┘
                               │  Vite proxy: /api → :5000
                               ▼
┌──────────────────────────────────────────────────────────────────────┐
│                     FLASK API SERVER (Port 5000)                     │
│                                                                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐               │
│  │ Auth API     │  │ Dashboard    │  │ Detection    │               │
│  │ /api/login   │  │ /api/stats   │  │ /api/detect/ │               │
│  │              │  │ /api/trend   │  │   manual     │               │
│  └──────────────┘  └──────────────┘  │   upload     │               │
│                                      │   paste      │               │
│  ┌──────────────┐  ┌──────────────┐  └──────┬───────┘               │
│  │ Alerts API   │  │ Users API    │         │                       │
│  │ /api/alerts  │  │ /api/users   │         ▼                       │
│  └──────────────┘  └──────────────┘  ┌──────────────┐               │
│                                      │  ML Pipeline │               │
│                                      └──────────────┘               │
└──────────────────────┬───────────────────────┬───────────────────────┘
                       │                       │
              ┌────────▼────────┐    ┌─────────▼──────────┐
              │   SQLite DB     │    │   ML Models (pkl)  │
              │ cloud_security  │    │ isolation_forest   │
              │   .db           │    │ scaler             │
              └─────────────────┘    └────────────────────┘
```

---

## ML Detection Pipeline

When a CSV/JSON file is uploaded (or manual event submitted), the following pipeline executes:

```
Input (CloudTrail Events)
       │
       ▼
┌──────────────────────────────────┐
│  1. CloudTrailPreprocessor       │  modules/preprocessor.py
│     extract_features()           │
│                                  │
│  Extracts 7 features per event:  │
│  • login_frequency               │  Rate of user logins in window
│  • api_call_count                │  API calls in rolling window
│  • time_of_access                │  Hour of day (0-23)
│  • geo_deviation                 │  Region deviation from norm
│  • privilege_weight              │  Action sensitivity score
│  • failed_login_count            │  Failed logins in window
│  • resource_sensitivity          │  Target resource sensitivity
└───────────────┬──────────────────┘
                │
                ▼
┌──────────────────────────────────┐
│  2. StandardScaler               │  models/scaler.pkl
│     transform()                  │
│                                  │
│  Normalizes features to zero     │
│  mean, unit variance             │
└───────────────┬──────────────────┘
                │
                ▼
┌──────────────────────────────────┐
│  3. AnomalyDetector              │  modules/anomaly_detector.py
│     predict() + score()          │  models/isolation_forest.pkl
│                                  │
│  Isolation Forest algorithm:     │
│  • Returns: -1 (anomaly)         │
│             +1 (normal)          │
│  • Anomaly score (continuous)    │
└───────────────┬──────────────────┘
                │
                ▼
┌──────────────────────────────────┐
│  4. RiskScorer                   │  modules/risk_scorer.py
│     calculate_risk_score()       │
│     get_severity()               │
│     get_threat_type()            │
│                                  │
│  Multi-factor risk scoring:      │
│  • Base: anomaly_score           │
│  • + privilege escalation bonus  │
│  • + geo-deviation bonus         │
│  • + failed login bonus          │
│                                  │
│  Outputs:                        │
│  • risk_score (0-100)            │
│  • severity (Critical/High/      │
│              Medium/Low)         │
│  • threat_type (classification)  │
└───────────────┬──────────────────┘
                │
                ▼
┌──────────────────────────────────┐
│  5. Insights Engine (app.py)     │
│                                  │
│  Aggregates batch results into:  │
│  • severity_breakdown            │
│  • threat_breakdown              │
│  • user_risk (per-user ranking)  │
│  • region_breakdown              │
│  • timeline (hourly buckets)     │
│  • high_risk_events (top 5)      │
└──────────────────────────────────┘
```

---

## Feature Engineering

| Feature | Type | Source | Description |
|---------|------|--------|-------------|
| `login_frequency` | float | User activity | Login events per hour in rolling window |
| `api_call_count` | int | User activity | Total API calls in rolling window |
| `time_of_access` | int | Event timestamp | Hour of day (0-23); off-hours weighted higher |
| `geo_deviation` | int | Region | 1 if region differs from user's most common region |
| `privilege_weight` | float | Action type | Sensitivity score of the AWS action (0-10) |
| `failed_login_count` | int | User activity | Failed login attempts in rolling window |
| `resource_sensitivity` | float | Resource ARN | Sensitivity score of target resource (0-10) |

### Privileged Actions (High Weight ≥ 8)

```
CreateUser, AttachUserPolicy, AttachGroupPolicy, AttachRolePolicy,
PutRolePolicy, CreateRole, CreateAccessKey, DeleteTrail,
StopLogging, UpdateTrail, AuthorizeSecurityGroupIngress,
AuthorizeSecurityGroupEgress
```

---

## Threat Classification

The `RiskScorer.get_threat_type()` classifies anomalies into:

| Threat Type | Trigger Conditions |
|-------------|-------------------|
| **Privilege Escalation Attempt** | High privilege_weight (≥ 8) |
| **Brute Force Attack** | High failed_login_count (≥ 3) |
| **Geographic Anomaly** | geo_deviation = 1 |
| **Off-Hours Access** | time_of_access outside 6-22 |
| **Suspicious API Activity** | Default fallback for detected anomalies |

---

## Risk Scoring Formula

```
base_score = normalize(anomaly_score) × 100

if privilege_weight >= 8:
    base_score × PRIVILEGE_ESCALATION_MULTIPLIER (1.5)

if geo_deviation == 1:
    base_score × GEO_DEVIATION_MULTIPLIER (1.2)

if failed_login_count >= 3:
    base_score += 20

final_score = clamp(base_score, 0, 100)
```

### Severity Thresholds

| Severity | Risk Score Range |
|----------|-----------------|
| Critical | ≥ 80 |
| High | ≥ 60 |
| Medium | ≥ 40 |
| Low | < 40 |

---

## Database Schema

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   raw_logs   │────▶│   features   │     │    alerts     │
├──────────────┤     ├──────────────┤     ├──────────────┤
│ id (PK)      │     │ id (PK)      │     │ id (PK)      │
│ event_id     │     │ log_id (FK)  │     │ log_id (FK)  │
│ user         │     │ login_freq   │     │ threat_type  │
│ timestamp    │     │ api_calls    │     │ risk_score   │
│ ip           │     │ time_access  │     │ severity     │
│ action       │     │ geo_dev      │     │ status       │
│ resource     │     │ priv_weight  │     │ created_at   │
│ region       │     │ failed_login │     │ closed_at    │
│ outcome      │     │ resource_sen │     │ closed_by(FK)│
│ raw_data     │     └──────────────┘     └──────────────┘
└──────────────┘
                                          ┌──────────────┐
                                          │    users     │
                                          ├──────────────┤
                                          │ id (PK)      │
                                          │ username     │
                                          │ password_hash│
                                          │ role         │
                                          │ created_at   │
                                          └──────────────┘
```

**Supported databases:** SQLite (default), MySQL (`mysql+pymysql://`), PostgreSQL (`postgresql://`)

---

## Frontend Architecture

```
src/
├── App.jsx                    # Router setup, protected routes
├── api/client.js              # Axios instance with auth headers
├── context/AuthContext.jsx    # Auth state, login/logout, RBAC
├── routes/ProtectedRoute.jsx  # Role-based route guard
│
├── pages/
│   ├── LoginPage.jsx          # Authentication form
│   ├── DashboardPage.jsx      # KPIs, charts, trends, top users
│   ├── AlertsPage.jsx         # Alert table with severity filter
│   ├── DetectPage.jsx         # Manual + Upload detection with insights
│   ├── ModelPage.jsx          # ML model configuration & metrics
│   └── UsersPage.jsx          # Admin: user CRUD
│
└── components/
    ├── Layout.jsx             # Sidebar navigation + main area
    ├── AlertTable.jsx         # Reusable alert list
    ├── AlertModal.jsx         # Alert detail modal
    ├── RiskScoreBar.jsx       # Visual risk score indicator
    ├── SeverityBadge.jsx      # Colored severity label
    ├── KpiCard.jsx            # Dashboard statistic card
    ├── LiveTicker.jsx         # Real-time alert feed
    └── charts/
        ├── TrendChart.jsx     # 24-hour anomaly line chart
        ├── SeverityChart.jsx  # Severity distribution bar chart
        ├── ThreatChart.jsx    # Threat type horizontal bar chart
        └── RadarChart.jsx     # Feature radar visualization
```

### Role-Based Access Control (RBAC)

| Role | Dashboard | Alerts | Detect | ML Model | Users |
|------|-----------|--------|--------|----------|-------|
| Admin | ✅ | ✅ | ✅ | ✅ | ✅ |
| Analyst | ✅ | ✅ | ✅ | ✅ | ❌ |
| Viewer | ✅ | ✅ | ✅ | ❌ | ❌ |

---

## Deployment Notes

### Development

```bash
# Backend (hot-reload via Flask debug mode)
python app.py

# Frontend (Vite HMR)
cd frontend && npm run dev
```

### Production Build

```bash
# Build React frontend
cd frontend
npm run build

# The built files go to frontend/dist/
# Flask serves them via the catch-all route
```

### Production Checklist

- [ ] Change `SECRET_KEY` in `.env` to a strong random value
- [ ] Set `FLASK_ENV=production` in `.env`
- [ ] Change default admin password
- [ ] Restrict CORS origins in `app.py` (currently `*`)
- [ ] Use a WSGI server (Gunicorn / Waitress) instead of Flask dev server
- [ ] Configure proper database (MySQL/PostgreSQL) for scale
- [ ] Set up HTTPS via reverse proxy (Nginx)
- [ ] Implement proper JWT authentication (current: mock tokens)
