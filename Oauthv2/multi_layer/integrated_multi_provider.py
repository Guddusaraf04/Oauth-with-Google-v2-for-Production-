"""
Multi-Provider OAuth Backend - Integrated with Your App
========================================================

Supports: Google, GitHub, Microsoft, Discord, Facebook, Twitter

Setup:
1. Save multi_provider_auth.py in your project folder
2. Replace your main.py with this file
3. Add provider credentials to .env
4. Run: python main.py
"""

from fastapi import FastAPI, Request, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse, RedirectResponse
from contextlib import asynccontextmanager
import os
from dotenv import load_dotenv
from typing import Optional
from enum import Enum

# Import multi-provider auth
try:
    from multi_provider_auth import MultiProviderAuth, OAuthProvider, PROVIDER_CONFIGS
    MULTI_PROVIDER_AVAILABLE = True
except ImportError:
    MULTI_PROVIDER_AVAILABLE = False
    print("⚠️  multi_provider_auth.py not found - multi-provider disabled")

# Import your existing auth system
from Auth import ProductionAuthLayer

# Load environment variables
load_dotenv()

# ============================================================================
# CONFIGURATION
# ============================================================================

# Initialize your existing auth (for JWT and token management)
auth = ProductionAuthLayer.from_env(
    use_redis=False,
    multi_tenant=False
)

# Initialize multi-provider auth (for OAuth flow)
multi_auth = None
if MULTI_PROVIDER_AVAILABLE:
    multi_auth = MultiProviderAuth()
    
    # Auto-detect and add configured providers
    providers_added = []
    
    # Google
    if os.getenv("GOOGLE_CLIENT_ID"):
        multi_auth.add_provider(
            OAuthProvider.GOOGLE,
            client_id=os.getenv("GOOGLE_CLIENT_ID"),
            client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
            redirect_uri=f"{os.getenv('BACKEND_URL', 'http://127.0.0.1:9000')}/auth/callback/google"
        )
        providers_added.append("google")
    
    # GitHub
    if os.getenv("GITHUB_CLIENT_ID"):
        multi_auth.add_provider(
            OAuthProvider.GITHUB,
            client_id=os.getenv("GITHUB_CLIENT_ID"),
            client_secret=os.getenv("GITHUB_CLIENT_SECRET"),
            redirect_uri=f"{os.getenv('BACKEND_URL', 'http://127.0.0.1:9000')}/auth/callback/github"
        )
        providers_added.append("github")
    
    # Microsoft
    if os.getenv("MICROSOFT_CLIENT_ID"):
        multi_auth.add_provider(
            OAuthProvider.MICROSOFT,
            client_id=os.getenv("MICROSOFT_CLIENT_ID"),
            client_secret=os.getenv("MICROSOFT_CLIENT_SECRET"),
            redirect_uri=f"{os.getenv('BACKEND_URL', 'http://127.0.0.1:9000')}/auth/callback/microsoft"
        )
        providers_added.append("microsoft")
    
    # Discord
    if os.getenv("DISCORD_CLIENT_ID"):
        multi_auth.add_provider(
            OAuthProvider.DISCORD,
            client_id=os.getenv("DISCORD_CLIENT_ID"),
            client_secret=os.getenv("DISCORD_CLIENT_SECRET"),
            redirect_uri=f"{os.getenv('BACKEND_URL', 'http://127.0.0.1:9000')}/auth/callback/discord"
        )
        providers_added.append("discord")
    
    # Facebook
    if os.getenv("FACEBOOK_CLIENT_ID"):
        multi_auth.add_provider(
            OAuthProvider.FACEBOOK,
            client_id=os.getenv("FACEBOOK_CLIENT_ID"),
            client_secret=os.getenv("FACEBOOK_CLIENT_SECRET"),
            redirect_uri=f"{os.getenv('BACKEND_URL', 'http://127.0.0.1:9000')}/auth/callback/facebook"
        )
        providers_added.append("facebook")
    
    # Twitter
    if os.getenv("TWITTER_CLIENT_ID"):
        multi_auth.add_provider(
            OAuthProvider.TWITTER,
            client_id=os.getenv("TWITTER_CLIENT_ID"),
            client_secret=os.getenv("TWITTER_CLIENT_SECRET"),
            redirect_uri=f"{os.getenv('BACKEND_URL', 'http://127.0.0.1:9000')}/auth/callback/twitter"
        )
        providers_added.append("twitter")
    
    if providers_added:
        print(f"✅ Multi-provider OAuth enabled: {', '.join(providers_added)}")
    else:
        print("⚠️  No OAuth providers configured - add credentials to .env")


# ============================================================================
# FASTAPI APP
# ============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Handle startup and shutdown events."""
    await auth.ensure_initialized()
    print("✅ Auth system initialized")
    yield
    await auth.shutdown()
    print("✅ Auth system shutdown")


app = FastAPI(
    title="Multi-Provider Auth API",
    description="OAuth with Google, GitHub, Microsoft, Discord, Facebook, Twitter",
    version="2.0.0",
    lifespan=lifespan
)

# CORS Configuration
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://127.0.0.1:9000")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_URL, "http://localhost:9000", "http://127.0.0.1:9000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Set-Cookie"],
)


# ============================================================================
# SERVE STATIC FRONTEND
# ============================================================================

@app.get("/", response_class=HTMLResponse)
async def serve_frontend():
    """Serve the main frontend page."""
    try:
        # Try multi-provider UI first if available
        if MULTI_PROVIDER_AVAILABLE and multi_auth and len(multi_auth.get_available_providers()) > 1:
            with open("multi_provider_login.html", "r", encoding="utf-8") as f:
                return f.read()
        else:
            # Fallback to single-provider UI
            with open("auth_frontend_html.html", "r", encoding="utf-8") as f:
                return f.read()
    except FileNotFoundError:
        return """
        <html><body>
        <h1>Frontend not found</h1>
        <p>Place auth_frontend_html.html or multi_provider_login.html in project root</p>
        <p><a href="/docs">API Documentation</a></p>
        </body></html>
        """


@app.get("/callback.html", response_class=HTMLResponse)
async def serve_callback():
    """Serve the callback page."""
    try:
        with open("callback.html", "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return "<html><body><h1>Callback page not found</h1></body></html>"


# ============================================================================
# MULTI-PROVIDER AUTH ROUTES
# ============================================================================

@app.get("/auth/providers")
async def list_providers():
    """List all available OAuth providers."""
    if not MULTI_PROVIDER_AVAILABLE or not multi_auth:
        return {"providers": ["google"]}  # Fallback to Google only
    
    providers = [p.value for p in multi_auth.get_available_providers()]
    
    return {
        "providers": providers,
        "count": len(providers),
        "default": providers[0] if providers else "google"
    }


@app.get("/auth/login/{provider}")
async def login_with_provider(provider: str, request: Request):
    """
    Initiate OAuth login with any provider.
    
    Example: /auth/login/google or /auth/login/github
    """
    print(f"\n{'='*60}")
    print(f"🔑 Login Request: {provider}")
    
    try:
        # Validate provider
        try:
            provider_enum = OAuthProvider(provider.lower())
        except ValueError:
            raise HTTPException(400, f"Unsupported provider: {provider}")
        
        if not MULTI_PROVIDER_AVAILABLE or not multi_auth:
            # Fallback to existing Google-only auth
            if provider.lower() == "google":
                return await auth.login_redirect(request)
            else:
                raise HTTPException(400, "Only Google login is available")
        
        # Get provider config
        config = multi_auth.get_provider_config(provider_enum)
        
        # Generate OAuth URL with PKCE
        import secrets
        import hashlib
        import base64
        from urllib.parse import urlencode
        
        state = secrets.token_urlsafe(32)
        verifier = secrets.token_urlsafe(64)
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode()).digest()
        ).decode().rstrip("=")
        
        # Store session
        backend = auth.get_tenant_backend(None)
        state_hash = hashlib.sha256(state.encode()).hexdigest()
        session_value = {
            "code_verifier": verifier,
            "provider": provider.lower(),
            "client_ip": request.client.host if request.client else None,
            "state_hash": state_hash,
        }
        
        await backend._store.set(
            f"auth:sess:{state}",
            session_value,
            900  # 15 minutes
        )
        await backend._store.set(
            f"auth:state:{state_hash}",
            {"valid": True},
            900
        )
        
        # Build OAuth URL
        params = {
            "response_type": "code",
            "client_id": config.client_id,
            "redirect_uri": config.authorize_url.replace(config.authorize_url.split('?')[0].split('/')[-1], f"callback/{provider}"),
            "scope": config.scope,
            "state": state,
        }
        
        if config.supports_pkce:
            params["code_challenge"] = challenge
            params["code_challenge_method"] = "S256"
        
        # Provider-specific parameters
        if provider_enum == OAuthProvider.GOOGLE:
            params["access_type"] = "offline"
            params["prompt"] = "consent"
            params["redirect_uri"] = f"{os.getenv('BACKEND_URL', 'http://127.0.0.1:9000')}/auth/callback/google"
        elif provider_enum == OAuthProvider.GITHUB:
            params["redirect_uri"] = f"{os.getenv('BACKEND_URL', 'http://127.0.0.1:9000')}/auth/callback/github"
        elif provider_enum == OAuthProvider.DISCORD:
            params["redirect_uri"] = f"{os.getenv('BACKEND_URL', 'http://127.0.0.1:9000')}/auth/callback/discord"
        
        url = f"{config.authorize_url}?{urlencode(params)}"
        
        print(f"   ✅ Redirecting to {provider} OAuth")
        print(f"{'='*60}\n")
        
        return RedirectResponse(url)
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"   ❌ Login error: {e}")
        import traceback
        traceback.print_exc()
        print(f"{'='*60}\n")
        raise HTTPException(500, f"Login failed: {str(e)}")


@app.get("/auth/callback/{provider}")
async def callback_with_provider(provider: str, request: Request):
    """
    Handle OAuth callback from any provider.
    
    Example: /auth/callback/google or /auth/callback/github
    """
    print(f"\n{'='*60}")
    print(f"🔄 OAuth Callback: {provider}")
    print(f"   Query params: {dict(request.query_params)}")
    
    try:
        # Validate provider
        try:
            provider_enum = OAuthProvider(provider.lower())
        except ValueError:
            raise HTTPException(400, f"Unsupported provider: {provider}")
        
        # For Google, use existing flow if multi-provider not available
        if provider.lower() == "google" and (not MULTI_PROVIDER_AVAILABLE or not multi_auth):
            result = await auth.handle_callback(request)
            return create_auth_response(result, provider)
        
        # Multi-provider flow
        state = request.query_params.get("state")
        code = request.query_params.get("code")
        error = request.query_params.get("error")
        
        if error:
            raise HTTPException(400, f"OAuth error: {error}")
        
        if not state or not code:
            raise HTTPException(400, "Missing state or code")
        
        # Validate state
        backend = auth.get_tenant_backend(None)
        state_hash = hashlib.sha256(state.encode()).hexdigest()
        state_valid = await backend._store.get(f"auth:state:{state_hash}")
        
        if not state_valid:
            raise HTTPException(400, "Invalid or expired state")
        
        await backend._store.delete(f"auth:state:{state_hash}")
        
        # Get session
        session = await backend._store.get(f"auth:sess:{state}")
        if not session:
            raise HTTPException(400, "Session expired")
        
        await backend._store.delete(f"auth:sess:{state}")
        
        # Get provider config
        config = multi_auth.get_provider_config(provider_enum)
        
        # Exchange code for token
        import httpx
        
        token_data = {
            "grant_type": "authorization_code",
            "client_id": config.client_id,
            "client_secret": config.client_secret,
            "code": code,
            "redirect_uri": f"{os.getenv('BACKEND_URL', 'http://127.0.0.1:9000')}/auth/callback/{provider}",
        }
        
        if config.supports_pkce:
            token_data["code_verifier"] = session.get("code_verifier")
        
        async with httpx.AsyncClient() as client:
            token_response = await client.post(
                config.token_url,
                data=token_data,
                headers={"Accept": "application/json"}
            )
            
            if token_response.status_code >= 400:
                raise HTTPException(400, f"Token exchange failed: {token_response.text}")
            
            tokens = token_response.json()
            access_token = tokens.get("access_token")
            
            if not access_token:
                raise HTTPException(400, "No access token received")
            
            # Get user info from provider
            user_info = await multi_auth.get_userinfo_from_provider(
                provider_enum,
                access_token
            )
            
            print(f"   ✅ User authenticated: {user_info.get('email')}")
            print(f"   Provider: {provider}")
            
            # Generate JWT tokens (using your existing system)
            import jwt
            import uuid
            from datetime import datetime, timedelta, timezone
            
            now = datetime.now(timezone.utc)
            exp = now + timedelta(minutes=10)
            jti = str(uuid.uuid4())
            
            payload = {
                "sub": user_info["unique_id"],  # Includes provider prefix
                "email": user_info.get("email"),
                "name": user_info.get("name"),
                "picture": user_info.get("picture"),
                "provider": provider.lower(),
                "iat": int(now.timestamp()),
                "exp": int(exp.timestamp()),
                "jti": jti,
                "iss": "MultiProviderAuth",
                "aud": config.client_id
            }
            
            access_jwt = jwt.encode(
                payload,
                os.getenv("APP_SECRET_KEY"),
                algorithm="HS256"
            )
            
            # Generate refresh token
            refresh_token = secrets.token_urlsafe(48)
            refresh_record = {
                "user_id": user_info["unique_id"],
                "provider": provider.lower(),
                "created_at": now.isoformat(),
                "jti": jti
            }
            
            await backend._store.set(
                f"auth:ref:{refresh_token}",
                refresh_record,
                30 * 86400  # 30 days
            )
            
            result = {
                "user": {
                    "id": user_info["unique_id"],
                    "email": user_info.get("email"),
                    "name": user_info.get("name"),
                    "picture": user_info.get("picture"),
                    "provider": provider.lower(),
                },
                "access_token": access_jwt,
                "token_type": "Bearer",
                "expires_in": 600,
                "refresh_token": refresh_token
            }
            
            print(f"   ✅ JWT tokens generated")
            print(f"{'='*60}\n")
            
            return create_auth_response(result, provider)
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"   ❌ Callback error: {e}")
        import traceback
        traceback.print_exc()
        print(f"{'='*60}\n")
        
        from urllib.parse import urlencode
        error_params = {"success": "false", "error": str(e)}
        return RedirectResponse(
            url=f"/callback.html?{urlencode(error_params)}",
            status_code=303
        )


def create_auth_response(result: dict, provider: str):
    """Create redirect response with cookies."""
    redirect_url = "/callback.html"
    response = RedirectResponse(url=redirect_url, status_code=303)
    
    cookie_settings = {
        "httponly": True,
        "samesite": "lax",
        "path": "/",
    }
    
    response.set_cookie(
        key="access_token",
        value=result["access_token"],
        max_age=result["expires_in"],
        **cookie_settings
    )
    
    response.set_cookie(
        key="refresh_token",
        value=result["refresh_token"],
        max_age=30 * 86400,
        **cookie_settings
    )
    
    # Store provider info
    response.set_cookie(
        key="auth_provider",
        value=provider.lower(),
        max_age=30 * 86400,
        httponly=False,  # Allow JS to read this
        **{k: v for k, v in cookie_settings.items() if k != 'httponly'}
    )
    
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    
    return response


# ============================================================================
# EXISTING AUTH ROUTES (unchanged)
# ============================================================================

@app.get("/health")
async def health():
    """Health check endpoint."""
    health_data = await auth.health_check()
    
    if MULTI_PROVIDER_AVAILABLE and multi_auth:
        health_data["multi_provider"] = "enabled"
        health_data["providers"] = [p.value for p in multi_auth.get_available_providers()]
    else:
        health_data["multi_provider"] = "disabled"
    
    return health_data


@app.get("/metrics")
async def metrics():
    """Get authentication metrics."""
    return await auth.get_metrics()


@app.get("/auth/profile")
async def get_profile(request: Request):
    """Get current user profile."""
    print(f"\n{'='*60}")
    print(f"📝 Profile Request")
    print(f"   Cookies: {list(request.cookies.keys())}")
    
    try:
        user_dependency = auth.user()
        user = await user_dependency.dependency(request)
        
        print(f"   ✅ User: {user.get('email')}")
        print(f"{'='*60}\n")
        
        return JSONResponse(content={
            "user": user,
            "message": "Profile retrieved successfully",
            "authenticated": True
        })
        
    except HTTPException as e:
        print(f"   ❌ Auth failed: {e.detail}")
        print(f"{'='*60}\n")
        return JSONResponse(
            status_code=e.status_code,
            content={"error": e.detail, "authenticated": False}
        )


@app.post("/auth/logout")
async def logout_endpoint(request: Request, user: dict = auth.user(optional=True)):
    """Logout user."""
    print(f"\n{'='*60}")
    print(f"🚪 Logout Request")
    
    try:
        refresh_token = request.cookies.get("refresh_token")
        
        if refresh_token:
            backend = auth.get_tenant_backend(None)
            try:
                await backend.revoke_refresh_token(refresh_token)
                print(f"   ✅ Refresh token revoked")
            except Exception as e:
                print(f"   ⚠️ Failed to revoke: {e}")
        
        response = JSONResponse(content={"success": True, "message": "Logged out"})
        response.delete_cookie("access_token", path="/")
        response.delete_cookie("refresh_token", path="/")
        response.delete_cookie("auth_provider", path="/")
        
        print(f"   ✅ Cookies cleared")
        print(f"{'='*60}\n")
        
        return response
        
    except Exception as e:
        print(f"   ❌ Logout error: {e}")
        print(f"{'='*60}\n")
        raise HTTPException(500, str(e))


@app.post("/auth/refresh")
async def refresh_token_endpoint(request: Request):
    """Refresh access token."""
    refresh_token = request.cookies.get("refresh_token")
    
    if not refresh_token:
        raise HTTPException(400, "Refresh token required")
    
    try:
        client_id = request.client.host if request.client else None
        backend = auth.get_tenant_backend(None)
        result = await backend.refresh_access_token(refresh_token, client_id)
        
        response = JSONResponse(content=result)
        
        cookie_settings = {"httponly": True, "samesite": "lax", "path": "/"}
        
        response.set_cookie(
            key="access_token",
            value=result["access_token"],
            max_age=result["expires_in"],
            **cookie_settings
        )
        response.set_cookie(
            key="refresh_token",
            value=result["refresh_token"],
            max_age=30 * 86400,
            **cookie_settings
        )
        
        return response
        
    except Exception as e:
        raise HTTPException(401, f"Token refresh failed: {str(e)}")


# Protected routes
@app.get("/api/protected")
async def protected_route(user: dict = auth.user()):
    """Protected endpoint."""
    return {
        "message": f"Hello {user.get('name', 'User')}!",
        "user_id": user.get("id"),
        "email": user.get("email"),
        "provider": user.get("_raw", {}).get("provider", "unknown"),
        "authenticated": True
    }


@app.get("/api/public")
async def public_route(user: dict = auth.user(optional=True)):
    """Public endpoint."""
    if user:
        return {
            "message": f"Welcome back, {user.get('name')}!",
            "authenticated": True,
            "provider": user.get("_raw", {}).get("provider")
        }
    return {"message": "Welcome, guest!", "authenticated": False}


# Debug endpoints
@app.get("/debug/cookies")
async def debug_cookies(request: Request):
    """Debug cookies."""
    return JSONResponse(content={
        "cookies": dict(request.cookies),
        "cookie_names": list(request.cookies.keys()),
        "has_access_token": "access_token" in request.cookies,
        "has_refresh_token": "refresh_token" in request.cookies,
        "auth_provider": request.cookies.get("auth_provider", "unknown")
    })


# ============================================================================
# RUN SERVER
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    
    print("""
    🚀 Multi-Provider Auth Server Starting
    
    📝 Setup:
    1. Add provider credentials to .env
    2. Configure redirect URIs in provider consoles
    3. Access at: http://127.0.0.1:9000
    
    📚 Docs: http://127.0.0.1:9000/docs
    🔍 Health: http://127.0.0.1:9000/health
    """)
    
    uvicorn.run(
        "main:app",
        host="127.0.0.1",
        port=9000,
        reload=True,
        log_level="info"
    )
