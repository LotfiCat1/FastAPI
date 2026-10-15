# My First App 🚀

A modular, production-grade REST API backend built in Python using Flask. This project showcases token authentication, role-based access control, in-memory data persistence, sliding window rate limiting, and structured audit logging.

---

## 🌟 Highlights & Features

- **Token Authentication**: Endpoints protected via API keys passed in `X-API-Key` or `Authorization: Bearer <token>`.
- **Role-Based Access Control**: Granular permission tiers (`admin`, `operator`, `viewer`, `guest`).
- **Resource Management**: Complete CRUD operations for System Users and Catalog Items.
- **Audit Logging**: Real-time chronological tracking for sensitive administrative actions.
- **Traffic Throttling**: Sliding window rate limiting to guard against abuse.
- **Diagnostics**: Built-in health check and runtime metrics endpoints.

---

## 🛠️ Getting Started

### Prerequisites

- Python 3.9+
- `pip` package manager

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/my-first-app.git
   cd my-first-app
   ```

2. Create a virtual environment and install dependencies:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. Launch the API service:
   ```bash
   python app.py
   ```

The service will bind by default to `http://0.0.0.0:8080`.

---

## 🔐 Authentication

All protected endpoints require an API token. You can pass your token using any of the following methods:

### Method 1: Custom Header (Recommended)
```http
X-API-Key: your_api_token_here
```

### Method 2: Bearer Authorization Header
```http
Authorization: Bearer your_api_token_here
```

### Method 3: Query Parameter (Development Only)
```http
GET /api/v1/items?api_key=your_api_token_here
```

---

## 📡 API Reference

### Public & Health Endpoints

| Method | Endpoint | Description | Auth Required |
|---|---|---|---|
| `GET` | `/` | API welcome banner and service metadata | No |
| `GET` | `/health` | Service uptime and catalog status | No |
| `POST` | `/api/v1/auth/verify` | Validate API token and inspect role | Yes |

### Resource Endpoints

| Method | Endpoint | Description | Required Role |
|---|---|---|---|
| `GET` | `/api/v1/users` | List registered system users | `admin`, `operator` |
| `POST` | `/api/v1/users` | Create a new user profile | `admin` |
| `GET` | `/api/v1/users/<id>` | Retrieve specific user details | `viewer`+ |
| `PUT` | `/api/v1/users/<id>` | Update user profile fields | `admin` |
| `DELETE` | `/api/v1/users/<id>` | Delete user account | `admin` |
| `GET` | `/api/v1/items` | List inventory items (supports `q`, `category`, `min_price`, `max_price`) | `viewer`+ |
| `POST` | `/api/v1/items` | Add a new inventory item | `operator`+ |
| `GET` | `/api/v1/items/<id>` | Retrieve item details | `viewer`+ |
| `PUT` | `/api/v1/items/<id>` | Modify inventory item | `operator`+ |
| `DELETE` | `/api/v1/items/<id>` | Delete inventory item | `admin` |
| `GET` | `/api/v1/audit/logs` | Query administrative audit trail | `admin` |

---

## 💡 Quick Examples

### Verifying a Token
```bash
curl -X POST http://localhost:8080/api/v1/auth/verify \
  -H "X-API-Key: YOUR_API_TOKEN"
```

### Searching Catalog Items
```bash
curl -X GET "http://localhost:8080/api/v1/items?q=router&max_price=500" \
  -H "Authorization: Bearer YOUR_API_TOKEN"
```

---

## ⚙️ Environment Configuration

| Variable | Default | Purpose |
|---|---|---|
| `APP_ENV` | `development` | Operating environment (`development`, `staging`, `production`) |
| `APP_PORT` | `8080` | Network port for HTTP listener |
| `APP_DEBUG` | `True` | Enable Flask debug mode and reloaders |
| `API_SECRET_TOKEN` | *(empty)* | Master administrative token for emergency access |
| `SECRET_KEY` | *(dev key)* | Session signing secret key |

---

## 📄 License

MIT License. Designed by Lotfi for modular learning and demonstration.
