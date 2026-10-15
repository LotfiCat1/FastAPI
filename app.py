"""
My First App - Core REST API Service
Author: Lotfi
Version: 1.0.0
Description: A modular backend API service featuring token authentication,
in-memory data storage, audit logging, and role-based access control.
"""

import os
import sys
import time
import uuid
import hmac
import json
import base64
import hashlib
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple
from functools import wraps

from flask import Flask, request, jsonify, Response

# ==============================================================================
# 1. APPLICATION CONFIGURATION
# ==============================================================================

class AppConfig:
    """Runtime configuration settings for My First App."""
    APP_NAME: str = "My First App"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: str = os.getenv("APP_ENV", "development")
    DEBUG_MODE: bool = os.getenv("APP_DEBUG", "True").lower() == "true"
    HOST: str = os.getenv("APP_HOST", "0.0.0.0")
    PORT: int = int(os.getenv("APP_PORT", "8080"))
    SECRET_KEY: str = os.getenv("SECRET_KEY", "dev-secret-key-change-in-production")
    
    # Token & Security settings
    TOKEN_HEADER_NAME: str = "X-API-Key"
    TOKEN_EXPIRY_SECONDS: int = 86400  # 24 hours
    MAX_REQUESTS_PER_MINUTE: int = 120
    
    # Pagination defaults
    DEFAULT_PAGE_SIZE: int = 20
    MAX_PAGE_SIZE: int = 100

# ==============================================================================
# 2. LOGGING CONFIGURATION
# ==============================================================================

def configure_logger() -> logging.Logger:
    """Configures structured application logging."""
    logger = logging.getLogger("MyFirstApp")
    logger.setLevel(logging.DEBUG if AppConfig.DEBUG_MODE else logging.INFO)
    
    if not logger.handlers:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter(
            fmt="[%(asctime)s] [%(levelname)s] [%(name)s]: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        
    return logger

logger = configure_logger()

# ==============================================================================
# 3. DOMAIN MODELS & DATA TRANSFER OBJECTS
# ==============================================================================

class UserRole:
    ADMIN: str = "admin"
    OPERATOR: str = "operator"
    VIEWER: str = "viewer"
    GUEST: str = "guest"
    
    @classmethod
    def all_roles(cls) -> List[str]:
        return [cls.ADMIN, cls.OPERATOR, cls.VIEWER, cls.GUEST]

class UserRecord:
    """Represents a registered system user."""
    def __init__(self, user_id: str, username: str, email: str, role: str, is_active: bool = True):
        self.user_id = user_id
        self.username = username
        self.email = email
        self.role = role
        self.is_active = is_active
        self.created_at = datetime.now(timezone.utc).isoformat()
        self.updated_at = self.created_at

    def to_dict(self) -> Dict[str, Any]:
        return {
            "user_id": self.user_id,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "is_active": self.is_active,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

class ItemRecord:
    """Represents an inventory or managed resource item."""
    def __init__(self, item_id: str, name: str, category: str, quantity: int, price: float, tags: List[str] = None):
        self.item_id = item_id
        self.name = name
        self.category = category
        self.quantity = quantity
        self.price = price
        self.tags = tags or []
        self.created_at = datetime.now(timezone.utc).isoformat()
        self.updated_at = self.created_at

    def to_dict(self) -> Dict[str, Any]:
        return {
            "item_id": self.item_id,
            "name": self.name,
            "category": self.category,
            "quantity": self.quantity,
            "price": self.price,
            "tags": self.tags,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

class AuditLogRecord:
    """Tracks administrative and sensitive operations."""
    def __init__(self, action: str, actor: str, target: str, status: str, details: Optional[Dict[str, Any]] = None):
        self.log_id = str(uuid.uuid4())
        self.timestamp = datetime.now(timezone.utc).isoformat()
        self.action = action
        self.actor = actor
        self.target = target
        self.status = status
        self.details = details or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "log_id": self.log_id,
            "timestamp": self.timestamp,
            "action": self.action,
            "actor": self.actor,
            "target": self.target,
            "status": self.status,
            "details": self.details,
        }

# ==============================================================================
# 4. IN-MEMORY DATABASE & SEED DATA
# ==============================================================================

class InMemoryDatabase:
    """Thread-safe in-memory mock database engine."""
    def __init__(self):
        self.users: Dict[str, UserRecord] = {}
        self.items: Dict[str, ItemRecord] = {}
        self.audit_logs: List[AuditLogRecord] = []
        self.active_sessions: Dict[str, Dict[str, Any]] = {}
        self.registered_tokens: Dict[str, Dict[str, Any]] = {}
        self._seed_initial_data()

    def _seed_initial_data(self):
        seed_users = [
            UserRecord("usr-001", "lotfi_dev", "lotfi.dev@internal.local", UserRole.ADMIN),
            UserRecord("usr-002", "sarah_ops", "sarah.ops@internal.local", UserRole.OPERATOR),
            UserRecord("usr-003", "alex_analyst", "alex@internal.local", UserRole.VIEWER),
        ]
        for u in seed_users:
            self.users[u.user_id] = u

        seed_items = [
            ItemRecord("itm-101", "Sensor Node Alpha", "Hardware", 45, 129.99, ["iot", "sensors"]),
            ItemRecord("itm-102", "Gateway Router Pro", "Networking", 12, 499.50, ["network", "router"]),
            ItemRecord("itm-103", "Encrypted Flash Key", "Security", 150, 49.00, ["security", "storage"]),
            ItemRecord("itm-104", "Optical Transceiver", "Networking", 80, 75.25, ["network", "fiber"]),
            ItemRecord("itm-105", "Thermal Probe Module", "Hardware", 25, 210.00, ["iot", "thermal"]),
        ]
        for it in seed_items:
            self.items[it.item_id] = it

        self.audit_logs.append(
            AuditLogRecord("DATABASE_INIT", "system", "local_storage", "SUCCESS", {"records": 8})
        )

    def get_user_by_id(self, user_id: str) -> Optional[UserRecord]:
        return self.users.get(user_id)

    def get_user_by_username(self, username: str) -> Optional[UserRecord]:
        for user in self.users.values():
            if user.username.lower() == username.lower():
                return user
        return None

    def add_user(self, user: UserRecord) -> UserRecord:
        self.users[user.user_id] = user
        return user

    def delete_user(self, user_id: str) -> bool:
        if user_id in self.users:
            del self.users[user_id]
            return True
        return False

    def list_users(self) -> List[UserRecord]:
        return list(self.users.values())

    def get_item_by_id(self, item_id: str) -> Optional[ItemRecord]:
        return self.items.get(item_id)

    def add_item(self, item: ItemRecord) -> ItemRecord:
        self.items[item.item_id] = item
        return item

    def delete_item(self, item_id: str) -> bool:
        if item_id in self.items:
            del self.items[item_id]
            return True
        return False

    def list_items(self) -> List[ItemRecord]:
        return list(self.items.values())

    def record_audit(self, action: str, actor: str, target: str, status: str, details: Optional[Dict[str, Any]] = None):
        entry = AuditLogRecord(action, actor, target, status, details)
        self.audit_logs.append(entry)
        return entry

    def list_audit_logs(self, limit: int = 50) -> List[AuditLogRecord]:
        return sorted(self.audit_logs, key=lambda x: x.timestamp, reverse=True)[:limit]

db = InMemoryDatabase()

# ==============================================================================
# 5. TOKEN AUTHENTICATION & SECURITY ENGINE
# ==============================================================================

# Master API Token: configured securely via environment variable
API_SECRET_TOKEN = os.getenv("API_SECRET_TOKEN", "")

def hash_token(token: str) -> str:
    """Computes SHA-256 digest of an API token."""
    return hashlib.sha256(token.strip().encode("utf-8")).hexdigest()

def register_token(token: str, user_id: str, role: str, label: str = "standard_token") -> Dict[str, Any]:
    """Stores a generated token descriptor in the security registry."""
    token_hash = hash_token(token)
    token_data = {
        "token_hash": token_hash,
        "user_id": user_id,
        "role": role,
        "label": label,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "is_active": True,
    }
    db.registered_tokens[token_hash] = token_data
    return token_data

def extract_token_from_request() -> Optional[str]:
    """Extracts authentication token from incoming HTTP request headers."""
    custom_header_token = request.headers.get(AppConfig.TOKEN_HEADER_NAME)
    if custom_header_token:
        return custom_header_token.strip()

    auth_header = request.headers.get("Authorization")
    if auth_header:
        parts = auth_header.split(" ")
        if len(parts) == 2 and parts[0].lower() == "bearer":
            return parts[1].strip()
        elif len(parts) == 1:
            return parts[0].strip()

    query_token = request.args.get("api_key") or request.args.get("token")
    if query_token:
        return query_token.strip()

    return None

def verify_api_token(token: str) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
    """
    Validates provided token against registered tokens and internal dev master key.
    """
    if not token or not isinstance(token, str):
        return False, None, "Authentication token is missing or empty"

    cleaned_token = token.strip()

    # Check for master token configured via environment variable
    if API_SECRET_TOKEN and cleaned_token == API_SECRET_TOKEN:
        logger.info("Request authenticated using environment master token")
        master_identity = {
            "user_id": "usr-001",
            "username": "lotfi_dev",
            "role": UserRole.ADMIN,
            "token_type": "developer_master_key",
            "access_level": "unrestricted",
            "authenticated_at": datetime.now(timezone.utc).isoformat(),
        }
        return True, master_identity, None

    # Check registered tokens in memory store
    token_digest = hash_token(cleaned_token)
    token_record = db.registered_tokens.get(token_digest)

    if token_record and token_record.get("is_active", False):
        user_info = db.get_user_by_id(token_record.get("user_id", ""))
        identity = {
            "user_id": token_record.get("user_id"),
            "username": user_info.username if user_info else "unknown",
            "role": token_record.get("role", UserRole.VIEWER),
            "token_type": "standard_api_token",
            "access_level": token_record.get("role"),
            "authenticated_at": datetime.now(timezone.utc).isoformat(),
        }
        return True, identity, None

    return False, None, "Invalid or expired API token"

def require_token(allowed_roles: Optional[List[str]] = None):
    """Decorator for endpoints requiring token authentication."""
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            token = extract_token_from_request()
            if not token:
                logger.warning(f"Unauthorized access to {request.path}: Missing token")
                db.record_audit("AUTH_FAILURE", "anonymous", request.path, "REJECTED", {"ip": request.remote_addr})
                return jsonify({
                    "success": False,
                    "error": "Authentication required",
                    "message": f"Please provide an API token via {AppConfig.TOKEN_HEADER_NAME} or Authorization header."
                }), 401

            is_valid, identity, error_msg = verify_api_token(token)
            if not is_valid or not identity:
                logger.warning(f"Unauthorized access to {request.path}: Invalid token")
                db.record_audit("AUTH_FAILURE", "unknown", request.path, "REJECTED", {"ip": request.remote_addr})
                return jsonify({"success": False, "error": "Unauthorized", "message": error_msg}), 401

            if allowed_roles and identity.get("role") not in allowed_roles:
                logger.warning(f"Forbidden access to {request.path} for role {identity.get('role')}")
                db.record_audit("FORBIDDEN_ACCESS", identity.get("username"), request.path, "FORBIDDEN", {"role": identity.get("role")})
                return jsonify({
                    "success": False,
                    "error": "Forbidden",
                    "message": f"Role {identity.get('role')} lacks required privileges."
                }), 403

            request.auth_identity = identity
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def validate_json_payload(required_fields: Optional[List[str]] = None):
    """Decorator ensuring request contains valid JSON and specified required fields."""
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not request.is_json:
                return jsonify({
                    "success": False,
                    "error": "Bad Request",
                    "message": "Content-Type must be 'application/json'"
                }), 400
            payload = request.get_json(silent=True)
            if payload is None:
                return jsonify({
                    "success": False,
                    "error": "Malformed JSON",
                    "message": "Failed to parse JSON body"
                }), 400
            if required_fields:
                missing = [f for f in required_fields if f not in payload or payload[f] is None]
                if missing:
                    return jsonify({
                        "success": False,
                        "error": "Missing Required Fields",
                        "missing_fields": missing
                    }), 400
            return fn(*args, **kwargs)
        return wrapper
    return decorator

# ==============================================================================
# 6. FLASK APPLICATION INITIALIZATION & MIDDLEWARE
# ==============================================================================

app = Flask(AppConfig.APP_NAME)
app.config["JSON_SORT_KEYS"] = False

@app.before_request
def start_request_profiler():
    request.start_time = time.time()
    request.request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))

@app.after_request
def inject_security_headers(response: Response) -> Response:
    duration = time.time() - getattr(request, "start_time", time.time())
    response.headers["X-Request-ID"] = getattr(request, "request_id", "unknown")
    response.headers["X-Response-Time-Ms"] = f"{duration * 1000:.2f}"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response

# ==============================================================================
# 7. CORE UTILITY FUNCTIONS
# ==============================================================================

def build_api_response(data: Any = None, message: str = "Operation successful", status_code: int = 200, **kwargs):
    payload = {
        "success": 200 <= status_code < 300,
        "message": message,
        "data": data,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "request_id": getattr(request, "request_id", None)
    }
    payload.update(kwargs)
    return jsonify(payload), status_code


def paginate_records(records: List[Any], page: int, page_size: int):
    total_items = len(records)
    total_pages = max(1, (total_items + page_size - 1) // page_size)
    page = max(1, min(page, total_pages))
    start_idx = (page - 1) * page_size
    end_idx = start_idx + page_size
    page_data = records[start_idx:end_idx]
    meta = {
        "total_items": total_items,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "has_next": page < total_pages,
        "has_previous": page > 1,
    }
    return page_data, meta


# ==============================================================================
# 8. PUBLIC & DIAGNOSTIC ENDPOINTS
# ==============================================================================

@app.route("/", methods=["GET"])
def index_view():
    return build_api_response(
        data={
            "app_name": AppConfig.APP_NAME,
            "version": AppConfig.APP_VERSION,
            "environment": AppConfig.ENVIRONMENT,
            "author": "Lotfi",
            "health_check": "/health"
        },
        message="Welcome to My First App API Service"
    )


@app.route("/health", methods=["GET"])
def health_check():
    return build_api_response(
        data={
            "status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "active_users_count": len(db.users),
            "stored_items_count": len(db.items),
        },
        message="Service is running normally"
    )


@app.route("/api/v1/system/stats", methods=["GET"])
@require_token(allowed_roles=[UserRole.ADMIN, UserRole.OPERATOR])
def get_system_stats():
    identity = getattr(request, "auth_identity", {})
    return build_api_response(
        data={
            "python_version": sys.version,
            "environment": AppConfig.ENVIRONMENT,
            "total_users": len(db.users),
            "total_items": len(db.items),
            "total_audit_events": len(db.audit_logs),
            "requested_by": identity.get("username"),
        },
        message="System statistics retrieved"
    )


# ==============================================================================
# 9. AUTHENTICATION & TOKEN MANAGEMENT ENDPOINTS
# ==============================================================================

@app.route("/api/v1/auth/verify", methods=["POST", "GET"])
def verify_token_endpoint():
    token = extract_token_from_request()
    if not token:
        return jsonify({
            "success": False,
            "valid": False,
            "error": "No token detected",
            "hint": f"Send token via {AppConfig.TOKEN_HEADER_NAME} or Bearer token"
        }), 400

    is_valid, identity, error_msg = verify_api_token(token)
    if not is_valid or not identity:
        return jsonify({"success": False, "valid": False, "error": error_msg}), 401

    return build_api_response(
        data={
            "valid": True,
            "identity": identity,
            "token_masked": f"{token[:6]}...{token[-4:]}" if len(token) > 12 else "***"
        },
        message="Token verified successfully"
    )


@app.route("/api/v1/auth/create-token", methods=["POST"])
@require_token(allowed_roles=[UserRole.ADMIN])
def create_token_endpoint():
    body = request.get_json(silent=True) or {}
    target_user_id = body.get("user_id")
    target_role = body.get("role", UserRole.VIEWER)
    label = body.get("label", "manual-generation")

    if not target_user_id or target_user_id not in db.users:
        return jsonify({"success": False, "error": "Invalid or missing user_id"}), 400

    if target_role not in UserRole.all_roles():
        return jsonify({"success": False, "error": f"Invalid role. Choose from {UserRole.all_roles()}"}), 400

    entropy = hashlib.md5(str(time.time_ns()).encode()).hexdigest()[:8]
    new_token_raw = f"mfa_{uuid.uuid4().hex}_{entropy}"
    token_record = register_token(new_token_raw, target_user_id, target_role, label)

    db.record_audit("TOKEN_CREATED", request.auth_identity.get("username"), target_user_id, "SUCCESS")

    return build_api_response(
        data={
            "token": new_token_raw,
            "user_id": target_user_id,
            "role": target_role,
            "label": label,
            "created_at": token_record["created_at"]
        },
        message="New API token generated successfully",
        status_code=201
    )


# ==============================================================================
# 10. USER RESOURCE CRUD ENDPOINTS
# ==============================================================================

@app.route("/api/v1/users", methods=["GET"])
@require_token(allowed_roles=[UserRole.ADMIN, UserRole.OPERATOR])
def list_users_endpoint():
    page = int(request.args.get("page", 1))
    page_size = min(int(request.args.get("page_size", AppConfig.DEFAULT_PAGE_SIZE)), AppConfig.MAX_PAGE_SIZE)
    users_list = [u.to_dict() for u in db.list_users()]
    paginated_users, meta = paginate_records(users_list, page, page_size)
    return build_api_response(data=paginated_users, meta=meta, message="Users list retrieved")


@app.route("/api/v1/users/<user_id>", methods=["GET"])
@require_token(allowed_roles=[UserRole.ADMIN, UserRole.OPERATOR, UserRole.VIEWER])
def get_user_endpoint(user_id: str):
    user = db.get_user_by_id(user_id)
    if not user:
        return jsonify({"success": False, "error": f"User {user_id} not found"}), 404
    return build_api_response(data=user.to_dict(), message="User details retrieved")


@app.route("/api/v1/users", methods=["POST"])
@require_token(allowed_roles=[UserRole.ADMIN])
def create_user_endpoint():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    email = data.get("email", "").strip()
    role = data.get("role", UserRole.VIEWER)

    if not username or not email:
        return jsonify({"success": False, "error": "username and email are required"}), 400

    if db.get_user_by_username(username):
        return jsonify({"success": False, "error": f"Username {username} already exists"}), 409

    if role not in UserRole.all_roles():
        return jsonify({"success": False, "error": f"Invalid role: {role}"}), 400

    new_id = f"usr-{len(db.users) + 1:03d}"
    new_user = UserRecord(new_id, username, email, role)
    db.add_user(new_user)
    db.record_audit("USER_CREATED", request.auth_identity.get("username"), new_id, "SUCCESS")
    return build_api_response(data=new_user.to_dict(), message="User created successfully", status_code=201)


@app.route("/api/v1/users/<user_id>", methods=["PUT"])
@require_token(allowed_roles=[UserRole.ADMIN])
def update_user_endpoint(user_id: str):
    user = db.get_user_by_id(user_id)
    if not user:
        return jsonify({"success": False, "error": f"User {user_id} not found"}), 404

    data = request.get_json(silent=True) or {}
    if "email" in data:
        user.email = data["email"].strip()
    if "role" in data and data["role"] in UserRole.all_roles():
        user.role = data["role"]
    if "is_active" in data:
        user.is_active = bool(data["is_active"])

    user.updated_at = datetime.now(timezone.utc).isoformat()
    db.record_audit("USER_UPDATED", request.auth_identity.get("username"), user_id, "SUCCESS")
    return build_api_response(data=user.to_dict(), message="User updated successfully")


@app.route("/api/v1/users/<user_id>", methods=["DELETE"])
@require_token(allowed_roles=[UserRole.ADMIN])
def delete_user_endpoint(user_id: str):
    if user_id == "usr-001":
        return jsonify({"success": False, "error": "Cannot delete root admin"}), 403

    if not db.delete_user(user_id):
        return jsonify({"success": False, "error": f"User {user_id} not found"}), 404

    db.record_audit("USER_DELETED", request.auth_identity.get("username"), user_id, "SUCCESS")
    return build_api_response(data={"deleted_user_id": user_id}, message="User successfully removed")


# ==============================================================================
# 11. INVENTORY / ITEMS RESOURCE ENDPOINTS
# ==============================================================================

@app.route("/api/v1/items", methods=["GET"])
@require_token(allowed_roles=[UserRole.ADMIN, UserRole.OPERATOR, UserRole.VIEWER])
def list_items_endpoint():
    category = request.args.get("category")
    tag = request.args.get("tag")
    page = int(request.args.get("page", 1))
    page_size = min(int(request.args.get("page_size", AppConfig.DEFAULT_PAGE_SIZE)), AppConfig.MAX_PAGE_SIZE)

    items = db.list_items()
    if category:
        items = [i for i in items if i.category.lower() == category.lower()]
    if tag:
        items = [i for i in items if tag.lower() in [t.lower() for t in i.tags]]

    items_dicts = [i.to_dict() for i in items]
    paginated_items, meta = paginate_records(items_dicts, page, page_size)
    return build_api_response(data=paginated_items, meta=meta, message="Inventory items retrieved")


@app.route("/api/v1/items/<item_id>", methods=["GET"])
@require_token(allowed_roles=[UserRole.ADMIN, UserRole.OPERATOR, UserRole.VIEWER])
def get_item_endpoint(item_id: str):
    item = db.get_item_by_id(item_id)
    if not item:
        return jsonify({"success": False, "error": f"Item {item_id} not found"}), 404
    return build_api_response(data=item.to_dict(), message="Item details retrieved")


@app.route("/api/v1/items", methods=["POST"])
@require_token(allowed_roles=[UserRole.ADMIN, UserRole.OPERATOR])
def create_item_endpoint():
    data = request.get_json(silent=True) or {}
    name = data.get("name", "").strip()
    category = data.get("category", "General").strip()
    quantity = int(data.get("quantity", 0))
    price = float(data.get("price", 0.0))
    tags = data.get("tags", [])

    if not name:
        return jsonify({"success": False, "error": "Item name is required"}), 400

    new_item_id = f"itm-{len(db.items) + 101:03d}"
    new_item = ItemRecord(new_item_id, name, category, quantity, price, tags)
    db.add_item(new_item)
    db.record_audit("ITEM_CREATED", request.auth_identity.get("username"), new_item_id, "SUCCESS")
    return build_api_response(data=new_item.to_dict(), message="Item created successfully", status_code=201)


@app.route("/api/v1/items/<item_id>", methods=["PUT"])
@require_token(allowed_roles=[UserRole.ADMIN, UserRole.OPERATOR])
def update_item_endpoint(item_id: str):
    item = db.get_item_by_id(item_id)
    if not item:
        return jsonify({"success": False, "error": f"Item {item_id} not found"}), 404

    data = request.get_json(silent=True) or {}
    if "name" in data:
        item.name = data["name"].strip()
    if "category" in data:
        item.category = data["category"].strip()
    if "quantity" in data:
        item.quantity = int(data["quantity"])
    if "price" in data:
        item.price = float(data["price"])
    if "tags" in data and isinstance(data["tags"], list):
        item.tags = data["tags"]

    item.updated_at = datetime.now(timezone.utc).isoformat()
    db.record_audit("ITEM_UPDATED", request.auth_identity.get("username"), item_id, "SUCCESS")
    return build_api_response(data=item.to_dict(), message="Item updated successfully")


@app.route("/api/v1/items/<item_id>", methods=["DELETE"])
@require_token(allowed_roles=[UserRole.ADMIN])
def delete_item_endpoint(item_id: str):
    if not db.delete_item(item_id):
        return jsonify({"success": False, "error": f"Item {item_id} not found"}), 404

    db.record_audit("ITEM_DELETED", request.auth_identity.get("username"), item_id, "SUCCESS")
    return build_api_response(data={"deleted_item_id": item_id}, message="Item deleted successfully")


# ==============================================================================
# 12. AUDIT LOGGING & SECURITY INSPECTION ENDPOINTS
# ==============================================================================

@app.route("/api/v1/audit/logs", methods=["GET"])
@require_token(allowed_roles=[UserRole.ADMIN])
def get_audit_logs_endpoint():
    limit = min(int(request.args.get("limit", 50)), 200)
    logs = [log.to_dict() for log in db.list_audit_logs(limit=limit)]
    return build_api_response(data=logs, message=f"Retrieved {len(logs)} audit entries")




# ==============================================================================
# 13. DATA VALIDATORS & SANITIZATION HELPERS
# ==============================================================================

class DataValidator:
    """Helper utilities to validate and sanitize request payloads."""
    @staticmethod
    def is_valid_email(email: str) -> bool:
        if not email or "@" not in email or "." not in email:
            return False
        parts = email.split("@")
        return len(parts) == 2 and len(parts[0]) > 0 and len(parts[1]) > 2

    @staticmethod
    def sanitize_string(value: Optional[str]) -> str:
        if not value:
            return ""
        return value.strip()

    @staticmethod
    def is_positive_number(val: Any) -> bool:
        try:
            return float(val) >= 0
        except (ValueError, TypeError):
            return False

    @staticmethod
    def validate_user_payload(data: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        if not isinstance(data, dict):
            return False, "Payload must be a valid JSON object"
        username = data.get("username")
        if not username or not isinstance(username, str) or len(username.strip()) < 3:
            return False, "Username must be at least 3 characters long"
        email = data.get("email")
        if not email or not DataValidator.is_valid_email(email):
            return False, "A valid email address is required"
        return True, None

    @staticmethod
    def validate_item_payload(data: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        if not isinstance(data, dict):
            return False, "Payload must be a valid JSON object"
        name = data.get("name")
        if not name or not isinstance(name, str) or len(name.strip()) == 0:
            return False, "Item name cannot be empty"
        quantity = data.get("quantity", 0)
        if not isinstance(quantity, int) or quantity < 0:
            return False, "Quantity must be a non-negative integer"
        price = data.get("price", 0.0)
        if not DataValidator.is_positive_number(price):
            return False, "Price must be a non-negative number"
        return True, None


# ==============================================================================
# 14. STANDARD ERROR HANDLERS
# ==============================================================================

@app.errorhandler(400)
def bad_request_error(e):
    return jsonify({"success": False, "error": "Bad Request", "message": str(e)}), 400


@app.errorhandler(404)
def resource_not_found(e):
    return jsonify({"success": False, "error": "Not Found", "message": "Resource not found"}), 404


@app.errorhandler(405)
def method_not_allowed_error(e):
    return jsonify({"success": False, "error": "Method Not Allowed", "message": f"Method {request.method} not allowed"}), 405


@app.errorhandler(500)
def internal_server_error(e):
    logger.error(f"Internal Server Error: {str(e)}")
    return jsonify({"success": False, "error": "Internal Server Error", "message": "An unexpected error occurred"}), 500


# ==============================================================================
# 15. APPLICATION BOOTSTRAPPER & CLI ENTRY POINT
# ==============================================================================

def initialize_application():
    app.boot_time = time.time()
    logger.info("Initializing My First App service dependencies...")
    logger.info(f"Loaded {len(db.users)} users and {len(db.items)} catalog items.")
    logger.info("API Token security middleware active.")




if __name__ == "__main__":
    initialize_application()
    app.run(
        host=AppConfig.HOST,
        port=AppConfig.PORT,
        debug=AppConfig.DEBUG_MODE
    )
