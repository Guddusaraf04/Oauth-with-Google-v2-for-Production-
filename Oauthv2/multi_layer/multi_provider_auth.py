"""
Multi-Provider OAuth Authentication System
==========================================

Supports: Google, GitHub, Microsoft, Discord, Facebook, Twitter/X

Author: Production Auth Team
Version: 1.0.0
"""

from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from enum import Enum
import httpx


class OAuthProvider(str, Enum):
    """Supported OAuth providers."""
    GOOGLE = "google"
    GITHUB = "github"
    MICROSOFT = "microsoft"
    DISCORD = "discord"
    FACEBOOK = "facebook"
    TWITTER = "twitter"


@dataclass
class OAuthConfig:
    """OAuth provider configuration."""
    provider: OAuthProvider
    client_id: str
    client_secret: str
    authorize_url: str
    token_url: str
    userinfo_url: str
    scope: str
    userinfo_method: str = "GET"  # GET or POST
    userinfo_headers_key: str = "Authorization"  # Where to put the token
    
    # Field mappings (how to extract user info from provider response)
    user_id_field: str = "id"
    email_field: str = "email"
    name_field: str = "name"
    picture_field: str = "picture"
    
    # Additional settings
    supports_pkce: bool = True
    requires_basic_auth: bool = False  # For token exchange


# ============================================================================
# PROVIDER CONFIGURATIONS
# ============================================================================

PROVIDER_CONFIGS = {
    OAuthProvider.GOOGLE: {
        "authorize_url": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_url": "https://oauth2.googleapis.com/token",
        "userinfo_url": "https://www.googleapis.com/oauth2/v2/userinfo",
        "scope": "openid email profile",
        "user_id_field": "id",
        "email_field": "email",
        "name_field": "name",
        "picture_field": "picture",
        "supports_pkce": True,
    },
    
    OAuthProvider.GITHUB: {
        "authorize_url": "https://github.com/login/oauth/authorize",
        "token_url": "https://github.com/login/oauth/access_token",
        "userinfo_url": "https://api.github.com/user",
        "scope": "read:user user:email",
        "user_id_field": "id",
        "email_field": "email",
        "name_field": "name",
        "picture_field": "avatar_url",
        "supports_pkce": True,
    },
    
    OAuthProvider.MICROSOFT: {
        "authorize_url": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        "token_url": "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        "userinfo_url": "https://graph.microsoft.com/v1.0/me",
        "scope": "openid email profile User.Read",
        "user_id_field": "id",
        "email_field": "mail",  # or userPrincipalName
        "name_field": "displayName",
        "picture_field": None,  # Requires separate call to /me/photo/$value
        "supports_pkce": True,
    },
    
    OAuthProvider.DISCORD: {
        "authorize_url": "https://discord.com/api/oauth2/authorize",
        "token_url": "https://discord.com/api/oauth2/token",
        "userinfo_url": "https://discord.com/api/users/@me",
        "scope": "identify email",
        "user_id_field": "id",
        "email_field": "email",
        "name_field": "username",
        "picture_field": "avatar",  # Needs special formatting
        "supports_pkce": True,
    },
    
    OAuthProvider.FACEBOOK: {
        "authorize_url": "https://www.facebook.com/v18.0/dialog/oauth",
        "token_url": "https://graph.facebook.com/v18.0/oauth/access_token",
        "userinfo_url": "https://graph.facebook.com/me?fields=id,name,email,picture",
        "scope": "email public_profile",
        "user_id_field": "id",
        "email_field": "email",
        "name_field": "name",
        "picture_field": "picture.data.url",
        "supports_pkce": False,
    },
    
    OAuthProvider.TWITTER: {
        "authorize_url": "https://twitter.com/i/oauth2/authorize",
        "token_url": "https://api.twitter.com/2/oauth2/token",
        "userinfo_url": "https://api.twitter.com/2/users/me",
        "scope": "tweet.read users.read",
        "user_id_field": "data.id",
        "email_field": None,  # Twitter doesn't provide email by default
        "name_field": "data.name",
        "picture_field": "data.profile_image_url",
        "supports_pkce": True,
        "requires_basic_auth": True,
    },
}


class MultiProviderAuth:
    """
    Multi-provider OAuth authentication system.
    
    Usage:
        # Setup with multiple providers
        auth = MultiProviderAuth()
        
        # Add Google
        auth.add_provider(
            OAuthProvider.GOOGLE,
            client_id="your-google-id",
            client_secret="your-google-secret",
            redirect_uri="http://localhost:8000/auth/callback/google"
        )
        
        # Add GitHub
        auth.add_provider(
            OAuthProvider.GITHUB,
            client_id="your-github-id",
            client_secret="your-github-secret",
            redirect_uri="http://localhost:8000/auth/callback/github"
        )
        
        # Use with FastAPI
        @app.get("/auth/login/{provider}")
        async def login(provider: OAuthProvider):
            return auth.get_login_redirect(provider)
    """
    
    def __init__(self):
        self.providers: Dict[OAuthProvider, OAuthConfig] = {}
    
    def add_provider(
        self,
        provider: OAuthProvider,
        client_id: str,
        client_secret: str,
        redirect_uri: str,
        scope: Optional[str] = None
    ) -> None:
        """
        Add an OAuth provider.
        
        Args:
            provider: Provider enum
            client_id: OAuth client ID
            client_secret: OAuth client secret
            redirect_uri: Callback URL for this provider
            scope: Optional custom scope (uses default if not provided)
        """
        base_config = PROVIDER_CONFIGS.get(provider)
        if not base_config:
            raise ValueError(f"Unsupported provider: {provider}")
        
        config = OAuthConfig(
            provider=provider,
            client_id=client_id,
            client_secret=client_secret,
            authorize_url=base_config["authorize_url"],
            token_url=base_config["token_url"],
            userinfo_url=base_config["userinfo_url"],
            scope=scope or base_config["scope"],
            user_id_field=base_config["user_id_field"],
            email_field=base_config["email_field"],
            name_field=base_config["name_field"],
            picture_field=base_config.get("picture_field"),
            supports_pkce=base_config.get("supports_pkce", True),
            requires_basic_auth=base_config.get("requires_basic_auth", False),
        )
        
        self.providers[provider] = config
        print(f"✅ Added OAuth provider: {provider.value}")
    
    def get_provider_config(self, provider: OAuthProvider) -> OAuthConfig:
        """Get configuration for a provider."""
        if provider not in self.providers:
            raise ValueError(f"Provider not configured: {provider}")
        return self.providers[provider]
    
    def get_available_providers(self) -> List[OAuthProvider]:
        """Get list of configured providers."""
        return list(self.providers.keys())
    
    async def get_userinfo_from_provider(
        self,
        provider: OAuthProvider,
        access_token: str
    ) -> Dict[str, Any]:
        """
        Fetch user info from provider using access token.
        
        Args:
            provider: OAuth provider
            access_token: Access token from provider
        
        Returns:
            Normalized user info dict with: id, email, name, picture, provider
        """
        config = self.get_provider_config(provider)
        
        # Make request to userinfo endpoint
        async with httpx.AsyncClient() as client:
            headers = {config.userinfo_headers_key: f"Bearer {access_token}"}
            
            if config.userinfo_method == "POST":
                response = await client.post(config.userinfo_url, headers=headers)
            else:
                response = await client.get(config.userinfo_url, headers=headers)
            
            response.raise_for_status()
            data = response.json()
        
        # Normalize user info (extract fields based on provider mapping)
        user_info = {
            "id": self._extract_field(data, config.user_id_field),
            "email": self._extract_field(data, config.email_field),
            "name": self._extract_field(data, config.name_field),
            "picture": self._extract_field(data, config.picture_field),
            "provider": provider.value,
            "provider_data": data,  # Keep original data
        }
        
        # Special handling for specific providers
        if provider == OAuthProvider.DISCORD and user_info["picture"]:
            # Discord avatar URL construction
            user_id = user_info["id"]
            avatar_hash = user_info["picture"]
            user_info["picture"] = f"https://cdn.discordapp.com/avatars/{user_id}/{avatar_hash}.png"
        
        elif provider == OAuthProvider.GITHUB and not user_info["email"]:
            # GitHub email might be private, fetch from emails endpoint
            async with httpx.AsyncClient() as client:
                email_response = await client.get(
                    "https://api.github.com/user/emails",
                    headers={"Authorization": f"Bearer {access_token}"}
                )
                emails = email_response.json()
                primary_email = next((e for e in emails if e.get("primary")), None)
                if primary_email:
                    user_info["email"] = primary_email["email"]
        
        # Create a unique user ID that includes provider
        user_info["unique_id"] = f"{provider.value}:{user_info['id']}"
        
        return user_info
    
    def _extract_field(self, data: Dict, field_path: Optional[str]) -> Optional[Any]:
        """
        Extract a field from nested dict using dot notation.
        
        Example: "picture.data.url" -> data["picture"]["data"]["url"]
        """
        if not field_path or not data:
            return None
        
        parts = field_path.split(".")
        value = data
        
        for part in parts:
            if isinstance(value, dict):
                value = value.get(part)
            else:
                return None
        
        return value


# ============================================================================
# USAGE EXAMPLE WITH FASTAPI
# ============================================================================

"""
# main.py

from fastapi import FastAPI, Request
from multi_provider_auth import MultiProviderAuth, OAuthProvider

app = FastAPI()

# Initialize multi-provider auth
multi_auth = MultiProviderAuth()

# Add providers from environment variables
multi_auth.add_provider(
    OAuthProvider.GOOGLE,
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    redirect_uri="http://localhost:8000/auth/callback/google"
)

multi_auth.add_provider(
    OAuthProvider.GITHUB,
    client_id=os.getenv("GITHUB_CLIENT_ID"),
    client_secret=os.getenv("GITHUB_CLIENT_SECRET"),
    redirect_uri="http://localhost:8000/auth/callback/github"
)

multi_auth.add_provider(
    OAuthProvider.DISCORD,
    client_id=os.getenv("DISCORD_CLIENT_ID"),
    client_secret=os.getenv("DISCORD_CLIENT_SECRET"),
    redirect_uri="http://localhost:8000/auth/callback/discord"
)


@app.get("/auth/login/{provider}")
async def login(provider: OAuthProvider, request: Request):
    '''Initiate OAuth login for any provider.'''
    # Use your existing google_auth.py logic but with multi_auth config
    config = multi_auth.get_provider_config(provider)
    # Generate redirect using config.authorize_url, etc.
    ...


@app.get("/auth/callback/{provider}")
async def callback(provider: OAuthProvider, request: Request):
    '''Handle OAuth callback for any provider.'''
    # 1. Exchange code for token (using provider config)
    # 2. Get user info: user_info = await multi_auth.get_userinfo_from_provider(provider, access_token)
    # 3. Generate JWT and set cookies (same as before)
    ...


@app.get("/auth/providers")
async def list_providers():
    '''List all available OAuth providers.'''
    return {
        "providers": [p.value for p in multi_auth.get_available_providers()]
    }
"""


# ============================================================================
# ENVIRONMENT VARIABLES TEMPLATE
# ============================================================================

"""
# .env file for multi-provider setup

# Google OAuth
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret

# GitHub OAuth
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret

# Microsoft OAuth
MICROSOFT_CLIENT_ID=your-microsoft-client-id
MICROSOFT_CLIENT_SECRET=your-microsoft-client-secret

# Discord OAuth
DISCORD_CLIENT_ID=your-discord-client-id
DISCORD_CLIENT_SECRET=your-discord-client-secret

# Facebook OAuth
FACEBOOK_CLIENT_ID=your-facebook-app-id
FACEBOOK_CLIENT_SECRET=your-facebook-app-secret

# Twitter OAuth
TWITTER_CLIENT_ID=your-twitter-client-id
TWITTER_CLIENT_SECRET=your-twitter-client-secret

# Common settings
APP_SECRET_KEY=your-jwt-secret-key
ENVIRONMENT=development
"""
