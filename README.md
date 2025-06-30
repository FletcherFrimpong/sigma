# SOC Dashboard

A standalone Security Operations Center (SOC) Dashboard with React frontend and FastAPI backend for monitoring security alerts and metrics.

## 🚀 Features

- **Real-time Alert Monitoring**: View and manage security alerts
- **Analyst Workload Tracking**: Monitor analyst assignments and workload
- **RESTful API**: FastAPI backend with comprehensive endpoints
- **Modern UI**: React-based dashboard with Material-UI components
- **Multi-platform Support**: Ready for integration with various SIEM systems

## 📋 Prerequisites

- Python 3.8+
- Node.js 14+
- npm or yarn

## 🛠️ Installation & Setup

### Backend (FastAPI)

1. **Navigate to backend directory:**
   ```bash
   cd backend
   ```

2. **Install Python dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Start the API server:**
   ```bash
   uvicorn main:app --reload --port 8000
   ```

   The API will be available at: http://localhost:8000

### Frontend (React)

1. **Navigate to frontend directory:**
   ```bash
   cd frontend-dashboard
   ```

2. **Install Node.js dependencies:**
   ```bash
   npm install
   ```

3. **Start the development server:**
   ```bash
   npm start
   ```

   The dashboard will be available at: http://localhost:3000

## 🔧 Configuration

### Environment Variables

Create a `.env` file in the backend directory:

```env
OPENAI_API_KEY=your_openai_api_key_here
```

### API Endpoints

The backend provides the following endpoints:

- `GET /dashboard/metrics` - Get dashboard metrics
- `GET /alerts/risky-signin` - Get risky sign-in alerts
- `POST /generate` - Generate detection rules
- `POST /analyze` - Analyze detection rules
- `POST /extract` - Extract threat intelligence

## 📁 Project Structure

```
Soc-dashboard/
├── backend/
│   ├── main.py              # FastAPI application
│   └── requirements.txt     # Python dependencies
├── frontend-dashboard/
│   ├── src/
│   │   ├── App.tsx         # Main React component
│   │   └── ...
│   ├── package.json        # Node.js dependencies
│   └── ...
└── README.md
```

## 🚀 Development

### Running Both Services

1. **Terminal 1 - Backend:**
   ```bash
   cd backend
   uvicorn main:app --reload --port 8000
   ```

2. **Terminal 2 - Frontend:**
   ```bash
   cd frontend-dashboard
   npm start
   ```

### API Documentation

Once the backend is running, visit:
- **Interactive API docs**: http://localhost:8000/docs
- **ReDoc documentation**: http://localhost:8000/redoc

## 🔗 Integration

This dashboard is designed to integrate with:
- SIEM systems (Splunk, ELK Stack, etc.)
- Security tools and APIs
- Custom alert sources

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## 📄 License

This project is licensed under the MIT License.

## 👨‍💻 Author

**Kwaw Fletcher Frimpong**

---

**Note**: This is a standalone version of the SOC Dashboard, separated from the main Sigma rule automation project for independent development and deployment. 