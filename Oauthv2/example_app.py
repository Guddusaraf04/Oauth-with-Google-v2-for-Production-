"""
Complete Production-Ready FastAPI Application
with Authentication and Security

This example demonstrates all the fixes and best practices.

Run with: uvicorn main:app --reload

Environment variables needed:
- OAUTH_CLIENT_ID
- OAUTH_CLIENT_SECRET
- APP_SECRET_KEY (generate with: python -c 'import secrets; print(secrets.token_urlsafe(32))')
- REDIS_URL (production only)
- ENVIRONMENT (development/staging/production)
"""

import os
import logging
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel

# Import fixed modules
from oauth import (
    setup_google_auth,
    google_user,
    login_url,
    login_redirect,
    handle_callback,
    logout_with_response,
    refresh_token,
    introspect_token,
    health_check as auth_health,
    get_metrics,
    shutdown as auth_shutdown
)
from secure import protect_production, protect_development

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'
)
logger = logging.getLogger(__name__)

# Load environment
ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
IS_PRODUCTION = ENVIRONMENT == "production"

# Validate critical environment variables
if IS_PRODUCTION:
    required_vars = [
        "OAUTH_CLIENT_ID",
        "OAUTH_CLIENT_SECRET", 
        "APP_SECRET_KEY",
        "REDIS_URL"
    ]
    missing = [var for var in required_vars if not os.getenv(var)]
    if missing:
        raise RuntimeError(
            f"Missing required environment variables: {', '.join(missing)}"
        )


# ============================================================================
# Application Lifespan
# ============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application startup and shutdown."""
    logger.info(f"Starting application in {ENVIRONMENT} mode...")
    
    # ========================================================================
    # STARTUP
    # ========================================================================
    
    # Initialize authentication
    try:
        auth_config = {
            "client_id": os.getenv("OAUTH_CLIENT_ID"),
            "client_secret": os.getenv("OAUTH_CLIENT_SECRET"),
            "app_secret_key": os.getenv("APP_SECRET_KEY"),
            "redirect_uri": os.getenv(
                "OAUTH_REDIRECT_URI",
                "http://localhost:8000/auth/callback"
            ),
            "authorize_url": "https://accounts.google.com/o/oauth2/v2/auth",
            "token_url": "https://oauth2.googleapis.com/token",
            "userinfo_url": "https://www.googleapis.com/oauth2/v2/userinfo",
            "environment": ENVIRONMENT,
            "access_expires_minutes": 10,  # Shorter is more secure
            "refresh_expires_days": 30,
            "enable_rate_limiting": True,
            "check_client_ip": IS_PRODUCTION,  # Enable in production
        }
        
        # Setup with Redis in production
        auth = setup_google_auth(
            config=auth_config,
            use_redis=IS_PRODUCTION,
            redis_url=os.getenv("REDIS_URL", "redis://localhost:6379/0")
        )
        
        await auth.initialize()
        logger.info("✓ Authentication system initialized")
        
    except Exception as e:
        logger.error(f"Failed to initialize auth: {e}", exc_info=True)
        raise
    
    # Setup monitoring (if configured)
    if os.getenv("SENTRY_DSN"):
        try:
            import sentry_sdk
            from sentry_sdk.integrations.fastapi import FastApiIntegration
            
            sentry_sdk.init(
                dsn=os.getenv("SENTRY_DSN"),
                environment=ENVIRONMENT,
                integrations=[FastApiIntegration()],
                traces_sample_rate=0.1 if IS_PRODUCTION else 1.0,
            )
            logger.info("✓ Sentry monitoring initialized")
        except ImportError:
            logger.warning("Sentry SDK not installed, monitoring disabled")
    
    logger.info("=" * 60)
    logger.info(f"Application started successfully in {ENVIRONMENT} mode")
    logger.info("=" * 60)
    
    yield
    
    # ========================================================================
    # SHUTDOWN
    # ========================================================================
    
    logger.info("Shutting down application...")
    
    try:
        await auth_shutdown()
        logger.info("✓ Authentication system shut down")
    except Exception as e:
        logger.error(f"Error during shutdown: {e}", exc_info=True)
    
    logger.info("Application shutdown complete")


# ============================================================================
# Create Application
# ============================================================================

app = FastAPI(
    title="Secure API",
    description="Production-ready API with OAuth2 authentication",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs" if not IS_PRODUCTION else None,  # Disable docs in prod
    redoc_url="/redoc" if not IS_PRODUCTION else None,
)


# ============================================================================
# Apply Security Middleware
# ============================================================================

if IS_PRODUCTION:
    protect_production(
        app,
        origins=os.getenv("ALLOWED_ORIGINS", "").split(","),
        redis_url=os.getenv("REDIS_URL")
    )
else:
    protect_development(app)

logger.info(f"✓ Security middleware applied ({ENVIRONMENT} mode)")


# ============================================================================
# Request/Response Models
# ============================================================================

class LoginResponse(BaseModel):
    """Login URL response."""
    login_url: str
    message: str = "Visit this URL to authenticate"


class UserProfile(BaseModel):
    """User profile response."""
    id: str
    email: str
    name: str
    picture: Optional[str] = None


class TokenRefreshRequest(BaseModel):
    """Token refresh request."""
    refresh_token: str


class TokenIntrospectRequest(BaseModel):
    """Token introspection request."""
    token: str


# ============================================================================
# Health & Monitoring Endpoints
# ============================================================================

@app.get("/health", tags=["monitoring"])
async def health():
    """
    Basic health check.
    
    Returns application health status.
    """
    return {
        "status": "healthy",
        "environment": ENVIRONMENT,
        "version": "1.0.0"
    }


@app.get("/health/detailed", tags=["monitoring"])
async def detailed_health():
    """
    Detailed health check including auth system.
    
    Returns comprehensive health status.
    """
    try:
        auth_status = await auth_health()
        return {
            "status": "healthy",
            "environment": ENVIRONMENT,
            "auth": auth_status,
            "version": "1.0.0"
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return JSONResponse(
            status_code=503,
            content={
                "status": "unhealthy",
                "error": str(e)
            }
        )


@app.get("/metrics", tags=["monitoring"])
async def metrics():
    """
    Get authentication metrics.
    
    Returns authentication system metrics.
    """
    try:
        return await get_metrics()
    except Exception as e:
        logger.error(f"Failed to get metrics: {e}")
        raise HTTPException(500, "Failed to retrieve metrics")


# ============================================================================
# Authentication Endpoints
# ============================================================================

@app.get("/auth/login", response_model=LoginResponse, tags=["authentication"])
async def get_login_url(request: Request):
    """
    Get Google OAuth login URL.
    
    Returns a URL that the client should redirect to for authentication.
    """
    try:
        url = await login_url(request)
        return LoginResponse(login_url=url)
    except Exception as e:
        logger.error(f"Failed to generate login URL: {e}")
        raise HTTPException(500, "Failed to generate login URL")


@app.get("/auth/login-redirect", tags=["authentication"])
async def redirect_to_login(request: Request):
    """
    Redirect directly to Google OAuth.
    
    Use this for server-side redirects instead of returning a URL.
    """
    try:
        return await login_redirect(request)
    except Exception as e:
        logger.error(f"Failed to redirect to login: {e}")
        raise HTTPException(500, "Failed to redirect to login")


@app.get("/auth/callback", tags=["authentication"])
async def auth_callback(request: Request):
    """
    Handle OAuth callback from Google.
    
    This endpoint receives the authorization code and exchanges it
    for tokens, then redirects to the frontend with user info.
    """
    try:
        frontend_url = os.getenv(
            "FRONTEND_URL",
            "http://localhost:3000"
        )
        return await handle_callback(request, frontend_url)
    except Exception as e:
        logger.error(f"Callback failed: {e}")
        # Redirect to frontend with error
        return RedirectResponse(
            url=f"{frontend_url}/callback?success=false&error=Authentication+failed"
        )


@app.post("/auth/logout", tags=["authentication"])
async def logout(request: Request, user=google_user(optional=True)):
    """
    Logout user and revoke tokens.
    
    Clears cookies and blacklists tokens.
    """
    try:
        return await logout_with_response(user_dict=user, request=request)
    except Exception as e:
        logger.error(f"Logout failed: {e}")
        raise HTTPException(500, "Logout failed")


@app.post("/auth/refresh", tags=["authentication"])
async def refresh_access_token(request: Request, data: TokenRefreshRequest):
    """
    Refresh access token using refresh token.
    
    Returns new access and refresh tokens.
    """
    try:
        return await refresh_token(
            refresh_token_str=data.refresh_token,
            request=request
        )
    except Exception as e:
        logger.error(f"Token refresh failed: {e}")
        raise HTTPException(401, "Token refresh failed")


@app.post("/auth/introspect", tags=["authentication"])
async def token_introspection(data: TokenIntrospectRequest):
    """
    Introspect a token (debugging/admin only).
    
    Returns token metadata and validity information.
    """
    try:
        return await introspect_token(data.token)
    except Exception as e:
        logger.error(f"Token introspection failed: {e}")
        raise HTTPException(401, "Token introspection failed")


# ============================================================================
# Protected Endpoints (Examples)
# ============================================================================

@app.get("/profile", response_model=UserProfile, tags=["users"])
async def get_profile(user=google_user()):
    """
    Get current user profile.
    
    Requires authentication. Returns user information from JWT token.
    """
    return UserProfile(
        id=user["id"],
        email=user["email"],
        name=user.get("name", ""),
        picture=user.get("picture")
    )


@app.get("/protected", tags=["examples"])
async def protected_route(user=google_user()):
    """
    Example protected route.
    
    Requires authentication. Only authenticated users can access.
    """
    return {
        "message": f"Hello, {user['email']}!",
        "user_id": user["id"],
        "authenticated": True
    }


@app.get("/optional-auth", tags=["examples"])
async def optional_auth_route(user=google_user(optional=True)):
    """
    Example route with optional authentication.
    
    Works for both authenticated and unauthenticated users.
    """
    if user:
        return {
            "message": f"Hello, {user['email']}!",
            "authenticated": True
        }
    else:
        return {
            "message": "Hello, guest!",
            "authenticated": False
        }


# ============================================================================
# Public Endpoints (Examples)
# ============================================================================

@app.get("/public", tags=["examples"])
async def public_route():
    """
    Example public route.
    
    No authentication required. Anyone can access.
    """
    return {
        "message": "This is a public endpoint",
        "authenticated": False
    }


@app.get("/", tags=["root"])
async def root():
    """
    API root endpoint.
    
    Returns basic API information.
    """
    return {
        "name": "Secure API",
        "version": "1.0.0",
        "environment": ENVIRONMENT,
        "docs": "/docs" if not IS_PRODUCTION else None,
        "endpoints": {
            "health": "/health",
            "login": "/auth/login",
            "profile": "/profile (requires auth)",
        }
    }


# ============================================================================
# Error Handlers
# ============================================================================

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Handle HTTP exceptions with consistent format."""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "status_code": exc.status_code,
            "path": str(request.url)
        }
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle unexpected exceptions."""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    
    # Don't expose internal errors in production
    if IS_PRODUCTION:
        message = "An internal error occurred"
    else:
        message = str(exc)
    
    return JSONResponse(
        status_code=500,
        content={
            "error": message,
            "status_code": 500,
            "path": str(request.url)
        }
    )


# ============================================================================
# Run Application
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    
    # Development settings
    if not IS_PRODUCTION:
        uvicorn.run(
            "main:app",
            host="0.0.0.0",
            port=8000,
            reload=True,
            log_level="info"
        )
    else:
        # Production settings
        uvicorn.run(
            "main:app",
            host="0.0.0.0",
            port=8000,
            workers=4,
            log_level="info",
            access_log=True
        )
