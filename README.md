# ☁️ Cloud Security Anomaly Detection System (ICAC-MDS)

An intelligent, real-time **cloud security monitoring platform** that uses **machine learning** to detect anomalous behavior in AWS CloudTrail logs. Built with a Flask backend, React dashboard, and Isolation Forest anomaly detection.

---

## 📋 Table of Contents

- [Features](#-features)
- [Tech Stack](#-tech-stack)
- [Prerequisites](#-prerequisites)
- [Quick Start](#-quick-start)
- [Project Structure](#-project-structure)
- [API Reference](#-api-reference)
- [Default Credentials](#-default-credentials)
- [Configuration](#-configuration)
- [Architecture](#-architecture)

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| **Real-time Dashboard** | Live security KPIs, anomaly trends, threat distribution charts |
| **Anomaly Detection** | Isolation Forest ML model trained on CloudTrail event data |
| **Batch Analysis** | Upload CSV/JSON datasets for bulk threat detection with rich insights |
| **Manual Detection** | Test individual events against the trained model |
| **Risk Scoring** | Multi-factor scoring: privilege escalation, geo-deviation, failed logins |
| **Threat Classification** | Auto-classifies threats: Privilege Escalation, Brute Force, Data Exfiltration, etc. |
| **Severity Levels** | Critical / High / Medium / Low severity with configurable thresholds |
| **Alert Management** | View, filter, and resolve security alerts |
| **User Management** | Role-based access (Admin, Analyst, Viewer) |
| **Insights Dashboard** | Visual analytics: severity distribution, user risk ranking, region hotspots, timeline |

---

## 🛠 Tech Stack

| Layer | Technology |
|-------|-----------|
| **Frontend** | React 18, Vite, Tailwind CSS, Recharts, Lucide Icons |
| **Backend** | Python 3.10+, Flask 3.0, Flask-CORS |
| **ML Engine** | scikit-learn (Isolation Forest), pandas, NumPy |
| **Database** | SQLite (default) / MySQL / PostgreSQL |
| **Auth** | Token-based with RBAC (Admin / Analyst / Viewer) |

---

## 📦 Prerequisites

- **Python** 3.10 or higher
- **Node.js** 18+ and **npm** 9+
- **pip** (Python package manager)

---

## 🚀 Quick Start

### 1. Clone & Navigate

```bash
git clone <repository-url>
cd CLOUD
```

### 2. Backend Setup

```bash
# Create and activate virtual environment
python -m venv venv

# Windows
venv\Scripts\activate

# macOS / Linux
source venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt
```

### 3. Environment Configuration

```bash
# Copy example env and edit as needed
cp .env.example .env
```

Edit `.env` with your settings:

```env
# Required
SECRET_KEY=your-secure-random-key

# Database (SQLite default — no setup needed)
DATABASE_URL=sqlite:///cloud_security.db

# Optional: AWS credentials for live CloudTrail
AWS_ACCESS_KEY_ID=your_key
AWS_SECRET_ACCESS_KEY=your_secret
AWS_REGION=us-east-1
```

### 4. Initialize Database & Train Model

```bash
# Generate sample data and initialize DB
python generate_sample_data.py

# Train the Isolation Forest model
python train.py
```

This creates:
- `cloud_security.db` — SQLite database with sample CloudTrail logs
- `models/isolation_forest.pkl` — Trained anomaly detection model
- `models/scaler.pkl` — Feature normalization scaler

### 5. Frontend Setup

```bash
cd frontend

# Install dependencies
npm install

# Return to project root
cd ..
```

### 6. Start the Application

**Terminal 1 — Backend (port 5000):**
```bash
python app.py
```

**Terminal 2 — Frontend (port 3000):**
```bash
cd frontend
npm run dev
```

### 7. Open in Browser

```
http://localhost:3000
```

---

## 🔐 Default Credentials

| Username | Password | Role |
|----------|----------|------|
| `admin` | `admin123` | Admin |

> ⚠️ **Change the default password before any production deployment.**

---

## 📁 Project Structure

```
CLOUD/
├── app.py                    # Flask API server (all endpoints)
├── config.py                 # Configuration (env vars, thresholds)
├── database.py               # SQLAlchemy models (RawLog, Feature, Alert, User)
├── train.py                  # Model training pipeline
├── generate_sample_data.py   # Sample CloudTrail data generator
├── requirements.txt          # Python dependencies
├── .env.example              # Environment variable template
│
├── modules/                  # Core ML & processing modules
│   ├── preprocessor.py       #   Feature engineering (7 features)
│   ├── anomaly_detector.py   #   Isolation Forest model wrapper
│   ├── risk_scorer.py        #   Multi-factor risk scoring
│   ├── alert_manager.py      #   Alert creation & management
│   └── cloudtrail_collector.py  # AWS CloudTrail data collector
│
├── models/                   # Trained ML artifacts
│   ├── isolation_forest.pkl  #   Trained Isolation Forest model
│   └── scaler.pkl            #   StandardScaler for features
│
├── frontend/                 # React dashboard
│   ├── src/
│   │   ├── pages/            #   Dashboard, Alerts, Detect, Model, Users, Login
│   │   ├── components/       #   AlertTable, RiskScoreBar, Charts, Layout
│   │   ├── api/              #   Axios API client
│   │   ├── context/          #   Auth context (RBAC)
│   │   └── routes/           #   Protected route wrapper
│   ├── package.json
│   └── vite.config.js        #   Dev server + API proxy to :5000
│
├── data/                     # Raw & processed data
├── test_data.json            # Sample detection test file
└── sample_dataset.csv        # Sample CSV for batch analysis
```

---

## 📡 API Reference

All endpoints are served at `http://localhost:5000`.

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/login` | Login, returns auth token |

### Dashboard

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/stats` | Dashboard KPIs & chart data |
| GET | `/api/trend` | 24-hour anomaly trend |

### Alerts

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/alerts` | List alerts (filter by severity/status) |
| GET | `/api/alerts/latest` | Latest 5 alerts (live ticker) |
| PUT | `/api/alerts/<id>/resolve` | Resolve an alert |

### Detection

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/detect/manual` | Analyze single CloudTrail event |
| POST | `/api/detect/upload` | Batch analysis from CSV/JSON file |
| POST | `/api/detect/paste` | Batch analysis from pasted data |

### Model

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/model/features` | Model configuration & feature info |

### Users (Admin only)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/users` | List all users |
| POST | `/api/users` | Create user |
| DELETE | `/api/users/<id>` | Delete user |

---

## ⚙️ Configuration

All configuration is in `config.py` and loaded from `.env`:

| Setting | Default | Description |
|---------|---------|-------------|
| `DATABASE_URL` | `sqlite:///cloud_security.db` | Database connection string |
| `SECRET_KEY` | `dev-secret-key-...` | Flask session secret |
| `FLASK_ENV` | `development` | Flask environment |
| `ISOLATION_FOREST_PARAMS` | `n_estimators=100, contamination=0.05` | ML model hyperparameters |
| `SEVERITY_THRESHOLDS` | `Critical: 80, High: 60, Medium: 40, Low: 0` | Risk score → severity mapping |
| `PRIVILEGE_ESCALATION_MULTIPLIER` | `1.5` | Risk multiplier for privilege escalation |

---

## 🏗 Architecture

See [ARCHITECTURE.md](./ARCHITECTURE.md) for detailed system architecture, data flow diagrams, and module documentation.

---

## 📄 License

This project is proprietary and confidential. All rights reserved.
