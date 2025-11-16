# Production Deployment Checklist

## ✅ Pre-Deployment Checklist

### 1. Environment Configuration

```bash
# .env.production
ENVIRONMENT=production

# OAuth Configuration
OAUTH_CLIENT_ID=your-google-client-id
OAUTH_CLIENT_SECRET=your-google-client-secret
OAUTH_REDIRECT_URI=https://api.yourdomain.com/auth/callback

# JWT Configuration - Generate strong secrets
APP_SECRET_KEY=$(python -c 'import secrets; print(secrets.token_urlsafe(32))')

# Redis Configuration (REQUIRED for production)
REDIS_URL=redis://your-redis-host:6379/0

# Frontend URLs
FRONTEND_URL=https://yourdomain.com
ALLOWED_ORIGINS=https://yourdomain.com,https://www.yourdomain.com

# Security Settings
RATE_LIMIT_CALLS=100
RATE_LIMIT_PERIOD=60
RATE_LIMIT_FAIL_OPEN=false

# Monitoring
SENTRY_DSN=your-sentry-dsn
LOG_LEVEL=INFO
```

### 2. Secret Generation

```python
# Generate strong secrets
import secrets

# For APP_SECRET_KEY (32+ characters)
print("APP_SECRET_KEY:", secrets.token_urlsafe(32))

# For JWT RS256 keys (if using RS256)
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Generate private key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

# Export private key
pem_private = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

# Export public key
pem_public = private_key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

print("Private Key:\n", pem_private.decode())
print("Public Key:\n", pem_public.decode())
```

### 3. Redis Setup

```bash
# Using Docker
docker run -d \
  --name redis \
  -p 6379:6379 \
  redis:7-alpine \
  redis-server --requirepass your-redis-password

# Or using Redis Cloud (recommended for production)
# Sign up at: https://redis.com/try-free/
```

### 4. Application Setup

```python
# main.py - Production Configuration
import os
from fastapi import FastAPI
from contextlib import asynccontextmanager
import logging

# Import fixed modules
from oauth import setup_google_auth, shutdown as auth_shutdown
from secure import protect_production

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logging.info("Starting application...")
    
    # Initialize auth
    auth = setup_google_auth(
        config={
            "client_id": os.getenv("OAUTH_CLIENT_ID"),
            "client_secret": os.getenv("OAUTH_CLIENT_SECRET"),
            "app_secret_key": os.getenv("APP_SECRET_KEY"),
            "redirect_uri": os.getenv("OAUTH_REDIRECT_URI"),
            "authorize_url": "https://accounts.google.com/o/oauth2/v2/auth",
            "token_url": "https://oauth2.googleapis.com/token",
            "userinfo_url": "https://www.googleapis.com/oauth2/v2/userinfo",
            "environment": "production",
            "access_expires_minutes": 10,  # Short-lived tokens
            "refresh_expires_days": 30,
            "enable_rate_limiting": True,
            "check_client_ip": True,
        },
        use_redis=True,
        redis_url=os.getenv("REDIS_URL")
    )
    
    await auth.initialize()
    logging.info("Auth system initialized")
    
    yield
    
    # Shutdown
    logging.info("Shutting down application...")
    await auth_shutdown()
    logging.info("Application shutdown complete")

app = FastAPI(
    title="Your API",
    version="1.0.0",
    lifespan=lifespan
)

# Apply security
protect_production(
    app,
    origins=os.getenv("ALLOWED_ORIGINS", "").split(","),
    redis_url=os.getenv("REDIS_URL")
)

# Your routes here
from oauth import google_user

@app.get("/profile")
async def profile(user=google_user()):
    return {"user": user}

@app.get("/public")
async def public(user=google_user(optional=True)):
    return {"user": user or "guest"}
```

## 🔒 Security Hardening

### 1. HTTPS Configuration

```nginx
# nginx.conf - HTTPS with strong ciphers
server {
    listen 443 ssl http2;
    server_name api.yourdomain.com;
    
    # SSL certificates
    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;
    
    # Strong SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    
    # HSTS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    
    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# Redirect HTTP to HTTPS
server {
    listen 80;
    server_name api.yourdomain.com;
    return 301 https://$server_name$request_uri;
}
```

### 2. Firewall Rules

```bash
# Allow only necessary ports
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp   # SSH
sudo ufw allow 80/tcp   # HTTP (for redirect)
sudo ufw allow 443/tcp  # HTTPS
sudo ufw enable

# Restrict Redis access (local only)
sudo ufw deny 6379/tcp
```

### 3. Rate Limiting at Multiple Layers

```python
# Application layer (already configured)
# + Nginx layer

# nginx.conf
http {
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    
    server {
        location /api/ {
            limit_req zone=api burst=20 nodelay;
            proxy_pass http://localhost:8000;
        }
    }
}
```

## 📊 Monitoring & Observability

### 1. Sentry Integration

```python
# Install: pip install sentry-sdk[fastapi]
import sentry_sdk
from sentry_sdk.integrations.fastapi import FastApiIntegration

sentry_sdk.init(
    dsn=os.getenv("SENTRY_DSN"),
    environment="production",
    integrations=[FastApiIntegration()],
    traces_sample_rate=0.1,  # 10% of transactions
)
```

### 2. Prometheus Metrics

```python
# Install: pip install prometheus-fastapi-instrumentator
from prometheus_fastapi_instrumentator import Instrumentator

@app.on_event("startup")
async def startup():
    Instrumentator().instrument(app).expose(app, endpoint="/metrics")
```

### 3. Structured Logging

```python
# Install: pip install python-json-logger
import logging
from pythonjsonlogger import jsonlogger

logHandler = logging.StreamHandler()
formatter = jsonlogger.JsonFormatter(
    '%(asctime)s %(name)s %(levelname)s %(message)s'
)
logHandler.setFormatter(formatter)
logging.root.addHandler(logHandler)
logging.root.setLevel(logging.INFO)
```

## 🧪 Testing

### 1. Security Tests

```python
# test_security.py
import pytest
from httpx import AsyncClient
from main import app

@pytest.mark.asyncio
async def test_rate_limiting():
    """Test that rate limiting works."""
    async with AsyncClient(app=app, base_url="http://test") as client:
        # Make many requests
        responses = []
        for _ in range(50):
            response = await client.get("/health")
            responses.append(response.status_code)
        
        # Should get 429 eventually
        assert 429 in responses

@pytest.mark.asyncio
async def test_authentication_required():
    """Test that protected endpoints require auth."""
    async with AsyncClient(app=app, base_url="http://test") as client:
        response = await client.get("/profile")
        assert response.status_code == 401

@pytest.mark.asyncio
async def test_https_redirect():
    """Test HTTPS redirect (if enabled)."""
    async with AsyncClient(app=app, base_url="http://test") as client:
        response = await client.get("/", follow_redirects=False)
        if response.status_code in [301, 302]:
            assert response.headers["location"].startswith("https://")
```

### 2. Load Testing

```bash
# Install: pip install locust

# locustfile.py
from locust import HttpUser, task, between

class APIUser(HttpUser):
    wait_time = between(1, 3)
    
    @task
    def health_check(self):
        self.client.get("/health")
    
    @task(3)
    def public_endpoint(self):
        self.client.get("/public")

# Run: locust -f locustfile.py --host=https://api.yourdomain.com
```

## 🚀 Deployment

### 1. Docker Deployment

```dockerfile
# Dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Non-root user
RUN useradd -m -u 1000 appuser && chown -R appuser:appuser /app
USER appuser

# Run application
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "4"]
```

```yaml
# docker-compose.yml
version: '3.8'

services:
  api:
    build: .
    ports:
      - "8000:8000"
    environment:
      - ENVIRONMENT=production
      - REDIS_URL=redis://redis:6379/0
    env_file:
      - .env.production
    depends_on:
      - redis
    restart: unless-stopped
  
  redis:
    image: redis:7-alpine
    command: redis-server --requirepass ${REDIS_PASSWORD}
    volumes:
      - redis-data:/data
    restart: unless-stopped

volumes:
  redis-data:
```

### 2. Kubernetes Deployment

```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  replicas: 3
  selector:
    matchLabels:
      app: api
  template:
    metadata:
      labels:
        app: api
    spec:
      containers:
      - name: api
        image: your-registry/api:latest
        ports:
        - containerPort: 8000
        env:
        - name: ENVIRONMENT
          value: "production"
        - name: REDIS_URL
          valueFrom:
            secretKeyRef:
              name: redis-secret
              key: url
        envFrom:
        - secretRef:
            name: api-secrets
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 5
```

## 📋 Post-Deployment Validation

### 1. Security Scan

```bash
# Run security checks
python -m pip install safety bandit

# Check dependencies
safety check

# Check code
bandit -r . -ll

# Check SSL
ssllabs-scan api.yourdomain.com
```

### 2. Performance Testing

```bash
# Install: pip install httpx

# test_performance.py
import asyncio
import time
import httpx

async def test_endpoint():
    async with httpx.AsyncClient() as client:
        start = time.time()
        response = await client.get("https://api.yourdomain.com/health")
        duration = time.time() - start
        return response.status_code, duration

async def run_tests(n=100):
    tasks = [test_endpoint() for _ in range(n)]
    results = await asyncio.gather(*tasks)
    
    durations = [r[1] for r in results]
    print(f"Average: {sum(durations)/len(durations):.3f}s")
    print(f"Min: {min(durations):.3f}s")
    print(f"Max: {max(durations):.3f}s")

asyncio.run(run_tests())
```

### 3. Monitoring Dashboard

```python
# Create health check dashboard
@app.get("/health/detailed")
async def detailed_health():
    from oauth import health_check, get_metrics
    
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "auth": await health_check(),
        "metrics": await get_metrics(),
        "redis": await check_redis_health(),
    }

async def check_redis_health():
    # Check Redis connection
    import redis.asyncio as aioredis
    try:
        client = aioredis.from_url(os.getenv("REDIS_URL"))
        await client.ping()
        await client.close()
        return {"status": "healthy"}
    except Exception as e:
        return {"status": "unhealthy", "error": str(e)}
```

## 🔔 Alerting

### 1. Set up alerts for:

- ❌ Authentication failures spike
- ❌ Rate limit hits increase
- ❌ Redis connection failures
- ❌ High error rates (>1%)
- ❌ Slow response times (>1s)
- ❌ SSL certificate expiring soon

### 2. Example Prometheus Alert Rules

```yaml
groups:
- name: api_alerts
  rules:
  - alert: HighErrorRate
    expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.01
    for: 5m
    annotations:
      summary: "High error rate detected"
  
  - alert: RateLimitHigh
    expr: rate(rate_limit_hits_total[5m]) > 10
    for: 5m
    annotations:
      summary: "High rate of rate limit hits"
```

## ✅ Final Checklist

Before going live:

- [ ] All secrets are strong and stored securely
- [ ] Redis is configured and tested
- [ ] HTTPS is enabled with valid certificates
- [ ] Rate limiting is tested and working
- [ ] Authentication flow is tested end-to-end
- [ ] Monitoring and alerting are configured
- [ ] Backups are configured (Redis snapshots)
- [ ] Load testing completed successfully
- [ ] Security scan passed
- [ ] Documentation is complete
- [ ] Rollback plan is documented
- [ ] Team is trained on incident response

## 🆘 Incident Response

If authentication is compromised:

1. **Immediate**: Rotate all secrets (APP_SECRET_KEY, OAUTH_CLIENT_SECRET)
2. **Revoke**: All active tokens using cleanup endpoint
3. **Investigate**: Check logs for unauthorized access
4. **Notify**: Affected users if data was accessed
5. **Review**: Security measures and update as needed

## 📞 Support Resources

- Redis Documentation: https://redis.io/docs/
- FastAPI Security: https://fastapi.tiangolo.com/tutorial/security/
- OAuth 2.0: https://oauth.net/2/
- OWASP Top 10: https://owasp.org/www-project-top-ten/
