"""
FastAPI Demo App - Complete OAuth Authentication System
========================================================

This demo showcases all authentication features including:
- Google OAuth login/logout
- Protected routes
- Token refresh
- User sessions
- Redis storage (optional)
- Health checks and metrics

Run with: uvicorn main:app --reload
"""

from fastapi import FastAPI, Request, Depends
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import logging
import os

# Import the authentication module
from oauth import (
    setup_google_auth,
    google_user,
    gu,  # Short alias
    login_url,
    login_redirect,
    handle_callback,
    logout,
    logout_with_response,
    refresh_token,
    verify_token,
    introspect_token,
    health_check,
    get_metrics,
    shutdown,
    RedisStorage
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ============================================================================
# APP CONFIGURATION
# ============================================================================

app = FastAPI(
    title="OAuth Demo API",
    description="Complete demo of Google OAuth authentication system",
    version="2.1.0"
)

# CORS middleware for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:8000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================================
# AUTHENTICATION SETUP
# ============================================================================

@app.on_event("startup")
async def startup_event():
    """Initialize authentication system on startup."""
    
    # Configuration from environment variables
    config = {
        "client_id": os.getenv("OAUTH_CLIENT_ID", "your-google-client-id.apps.googleusercontent.com"),
        "client_secret": os.getenv("OAUTH_CLIENT_SECRET", "your-client-secret"),
        "app_secret_key": os.getenv("APP_SECRET_KEY", "your-secure-random-key-min-32-chars"),
        "redirect_uri": os.getenv("REDIRECT_URI", "http://localhost:8000/auth/callback"),
        "authorize_url": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_url": "https://oauth2.googleapis.com/token",
        "userinfo_url": "https://www.googleapis.com/oauth2/v2/userinfo",
        "environment": os.getenv("ENVIRONMENT", "development"),
        
        # Optional: Customize token expiration
        "access_expires_minutes": 15,
        "refresh_expires_days": 30,
        
        # Optional: Enable/disable features
        "check_client_ip": True,
        "enable_rate_limiting": True,
        "enable_token_blacklist": True,
    }
    
    # Choose storage backend
    use_redis = os.getenv("USE_REDIS", "false").lower() == "true"
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    
    try:
        # Initialize authentication
        auth = setup_google_auth(
            config=config,
            use_redis=use_redis,
            redis_url=redis_url
        )
        
        # Initialize async components
        await auth.initialize()
        
        logger.info("✅ Authentication system initialized successfully")
        logger.info(f"   Environment: {config['environment']}")
        logger.info(f"   Redis: {'Enabled' if use_redis else 'Disabled (in-memory)'}")
        logger.info(f"   Redirect URI: {config['redirect_uri']}")
        
    except Exception as e:
        logger.error(f"❌ Failed to initialize authentication: {e}")
        raise


@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown."""
    await shutdown()
    logger.info("Authentication system shutdown complete")


# ============================================================================
# PUBLIC ROUTES
# ============================================================================

@app.get("/", response_class=HTMLResponse)
async def home():
    """Home page with navigation."""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>OAuth Demo</title>
        <style>
            body { font-family: Arial; max-width: 800px; margin: 50px auto; padding: 20px; }
            h1 { color: #333; }
            .section { background: #f5f5f5; padding: 20px; margin: 20px 0; border-radius: 8px; }
            a { color: #4285f4; text-decoration: none; }
            a:hover { text-decoration: underline; }
            .endpoint { background: white; padding: 10px; margin: 10px 0; border-left: 3px solid #4285f4; }
            code { background: #f0f0f0; padding: 2px 6px; border-radius: 3px; }
        </style>
    </head>
    <body>
        <h1>🔐 OAuth Authentication Demo</h1>
        
        <div class="section">
            <h2>Authentication Endpoints</h2>
            <div class="endpoint">
                <strong>Login (Redirect):</strong><br>
                <a href="/auth/login">/auth/login</a> - Redirects to Google OAuth
            </div>
            <div class="endpoint">
                <strong>Login (Get URL):</strong><br>
                <a href="/auth/login-url">/auth/login-url</a> - Returns login URL as JSON
            </div>
            <div class="endpoint">
                <strong>Callback:</strong><br>
                <code>/auth/callback</code> - OAuth callback (automatic)
            </div>
            <div class="endpoint">
                <strong>Logout:</strong><br>
                <a href="/auth/logout" onclick="return confirm('Logout?')">/auth/logout</a> - Logout and revoke tokens
            </div>
        </div>
        
        <div class="section">
            <h2>Protected Routes (Requires Login)</h2>
            <div class="endpoint">
                <a href="/profile">/profile</a> - View your profile
            </div>
            <div class="endpoint">
                <a href="/dashboard">/dashboard</a> - User dashboard
            </div>
            <div class="endpoint">
                <a href="/api/user">/api/user</a> - Get user info (JSON)
            </div>
        </div>
        
        <div class="section">
            <h2>Public Routes</h2>
            <div class="endpoint">
                <a href="/public">/public</a> - Public page (optional auth)
            </div>
            <div class="endpoint">
                <a href="/welcome">/welcome</a> - Welcome page (shows name if logged in)
            </div>
        </div>
        
        <div class="section">
            <h2>Token Management</h2>
            <div class="endpoint">
                <a href="/auth/refresh">/auth/refresh</a> - Refresh access token
            </div>
            <div class="endpoint">
                <a href="/auth/introspect">/auth/introspect</a> - Inspect current token
            </div>
        </div>
        
        <div class="section">
            <h2>System Endpoints</h2>
            <div class="endpoint">
                <a href="/auth/health">/auth/health</a> - System health check
            </div>
            <div class="endpoint">
                <a href="/auth/metrics">/auth/metrics</a> - Authentication metrics
            </div>
            <div class="endpoint">
                <a href="/docs">/docs</a> - API Documentation (Swagger)
            </div>
        </div>
    </body>
    </html>
    """


# ============================================================================
# AUTHENTICATION ROUTES
# ============================================================================

@app.get("/auth/login")
async def login(request: Request):
    """Redirect to Google OAuth login page."""
    return await login_redirect(request)


@app.get("/auth/login-url")
async def get_login_url(request: Request):
    """Get login URL without redirect (for frontend integration)."""
    url = await login_url(request)
    return {"login_url": url, "message": "Use this URL to initiate login"}


@app.get("/auth/callback")
async def callback(request: Request):
    """
    OAuth callback endpoint.
    
    Handles the redirect from Google and sets authentication cookies.
    """
    # Customize frontend URL if needed
    frontend_url = os.getenv("FRONTEND_URL", "http://localhost:8000")
    return await handle_callback(request, frontend_url)


@app.post("/auth/logout")
@app.get("/auth/logout")
async def logout_endpoint(
    request: Request,
    user=Depends(google_user(optional=True))
):
    """
    Logout current user.
    
    Revokes tokens and clears cookies.
    """
    return await logout_with_response(user_dict=user, request=request)


@app.post("/auth/refresh")
async def refresh_endpoint(request: Request):
    """
    Refresh access token using refresh token.
    
    The refresh token is automatically read from cookies.
    """
    try:
        result = await refresh_token(request=request)
        
        # Return new tokens and optionally set cookies
        response = JSONResponse(content=result)
        
        # Set new access token cookie
        response.set_cookie(
            key="access_token",
            value=result["access_token"],
            max_age=result["expires_in"],
            httponly=True,
            secure=False,  # Set to True in production with HTTPS
            samesite="lax"
        )
        
        return response
    except Exception as e:
        logger.error(f"Token refresh failed: {e}")
        return JSONResponse(
            status_code=401,
            content={"error": "Token refresh failed", "detail": str(e)}
        )


@app.post("/auth/verify")
async def verify_endpoint(token: str):
    """
    Verify a JWT token.
    
    Usage: POST /auth/verify with JSON body: {"token": "your-token"}
    """
    return await verify_token(token)


@app.post("/auth/introspect")
@app.get("/auth/introspect")
async def introspect_endpoint(request: Request):
    """
    Introspect current access token.
    
    Shows token metadata and expiration info.
    """
    token = request.cookies.get("access_token")
    if not token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split()[1]
    
    if not token:
        return JSONResponse(
            status_code=400,
            content={"error": "No token provided"}
        )
    
    return await introspect_token(token)


# ============================================================================
# PROTECTED ROUTES (Require Authentication)
# ============================================================================

@app.get("/profile", response_class=HTMLResponse)
async def profile(user=Depends(google_user())):
    """
    User profile page (protected).
    
    Demonstrates: Required authentication with google_user()
    """
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Profile</title>
        <style>
            body {{ font-family: Arial; max-width: 600px; margin: 50px auto; padding: 20px; }}
            .profile {{ background: #f5f5f5; padding: 20px; border-radius: 8px; }}
            img {{ border-radius: 50%; width: 100px; height: 100px; }}
            .info {{ margin: 20px 0; }}
            .label {{ font-weight: bold; color: #666; }}
            a {{ color: #4285f4; text-decoration: none; }}
        </style>
    </head>
    <body>
        <h1>👤 Your Profile</h1>
        <div class="profile">
            {f'<img src="{user.get("picture")}" alt="Profile">' if user.get("picture") else ''}
            <div class="info">
                <div><span class="label">Name:</span> {user.get("name", "N/A")}</div>
                <div><span class="label">Email:</span> {user.get("email", "N/A")}</div>
                <div><span class="label">ID:</span> {user.get("id", "N/A")}</div>
                <div><span class="label">Verified:</span> {user.get("email_verified", False)}</div>
            </div>
        </div>
        <p><a href="/">← Back to Home</a> | <a href="/auth/logout">Logout</a></p>
    </body>
    </html>
    """


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(user=Depends(google_user())):
    """
    User dashboard (protected).
    
    Demonstrates: Required authentication
    """
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Dashboard</title>
        <style>
            body {{ font-family: Arial; max-width: 800px; margin: 50px auto; padding: 20px; }}
            .welcome {{ background: #4285f4; color: white; padding: 20px; border-radius: 8px; }}
            .stats {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin: 20px 0; }}
            .stat {{ background: #f5f5f5; padding: 20px; border-radius: 8px; text-align: center; }}
            .stat-value {{ font-size: 2em; font-weight: bold; color: #4285f4; }}
        </style>
    </head>
    <body>
        <div class="welcome">
            <h1>Welcome, {user.get("name", "User")}! 👋</h1>
            <p>Email: {user.get("email")}</p>
        </div>
        
        <h2>Your Dashboard</h2>
        <div class="stats">
            <div class="stat">
                <div class="stat-value">✅</div>
                <div>Authenticated</div>
            </div>
            <div class="stat">
                <div class="stat-value">🔐</div>
                <div>Secure Session</div>
            </div>
            <div class="stat">
                <div class="stat-value">🎉</div>
                <div>Welcome Back</div>
            </div>
        </div>
        
        <p><a href="/">← Back to Home</a> | <a href="/auth/logout">Logout</a></p>
    </body>
    </html>
    """


@app.get("/api/user")
async def get_user(user=Depends(google_user())):
    """
    Get current user info as JSON (protected).
    
    Demonstrates: API endpoint with required authentication
    """
    return {
        "success": True,
        "user": user
    }


# ============================================================================
# PUBLIC ROUTES WITH OPTIONAL AUTHENTICATION
# ============================================================================

@app.get("/public", response_class=HTMLResponse)
async def public_page(user=Depends(google_user(optional=True))):
    """
    Public page with optional authentication.
    
    Demonstrates: optional=True allows both authenticated and guest access
    """
    if user:
        content = f"""
        <h1>Hello, {user.get("name")}! 👋</h1>
        <p>You are logged in as {user.get("email")}</p>
        <p><a href="/profile">View Profile</a> | <a href="/auth/logout">Logout</a></p>
        """
    else:
        content = """
        <h1>Welcome, Guest! 👤</h1>
        <p>You are not logged in. This is a public page.</p>
        <p><a href="/auth/login">Login with Google</a></p>
        """
    
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Public Page</title>
        <style>
            body {{ font-family: Arial; max-width: 600px; margin: 50px auto; padding: 20px; }}
            a {{ color: #4285f4; text-decoration: none; }}
        </style>
    </head>
    <body>
        {content}
        <p><a href="/">← Back to Home</a></p>
    </body>
    </html>
    """


@app.get("/welcome")
async def welcome(user=Depends(gu(optional=True))):
    """
    Welcome page using short alias 'gu'.
    
    Demonstrates: Using the ultra-short 'gu' alias instead of 'google_user'
    """
    name = user.get("name") if user else "Guest"
    status = "authenticated" if user else "guest"
    
    return {
        "message": f"Welcome, {name}!",
        "status": status,
        "user": user
    }


# ============================================================================
# SYSTEM ROUTES
# ============================================================================

@app.get("/auth/health")
async def health():
    """
    Health check endpoint.
    
    Returns system status and metrics.
    """
    return await health_check()


@app.get("/auth/metrics")
async def metrics():
    """
    Get authentication metrics.
    
    Shows login counts, token refreshes, rate limit hits, etc.
    """
    return await get_metrics()


# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.exception_handler(401)
async def unauthorized_handler(request: Request, exc):
    """Custom 401 error handler."""
    return HTMLResponse(
        content="""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Unauthorized</title>
            <style>
                body { font-family: Arial; max-width: 600px; margin: 50px auto; 
                       padding: 20px; text-align: center; }
                .error { background: #fee; border: 2px solid #c33; 
                        padding: 30px; border-radius: 8px; }
            </style>
        </head>
        <body>
            <div class="error">
                <h1>🔒 Authentication Required</h1>
                <p>You need to be logged in to access this page.</p>
                <p><a href="/auth/login">Login with Google</a></p>
            </div>
            <p><a href="/">← Back to Home</a></p>
        </body>
        </html>
        """,
        status_code=401
    )


# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║           OAuth Authentication Demo Server                   ║
    ║                                                              ║
    ║  Server starting at: http://localhost:8000                  ║
    ║  Documentation: http://localhost:8000/docs                  ║
    ║                                                              ║
    ║  Quick Start:                                               ║
    ║  1. Visit http://localhost:8000                            ║
    ║  2. Click "Login" to authenticate with Google               ║
    ║  3. Explore protected and public routes                     ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
