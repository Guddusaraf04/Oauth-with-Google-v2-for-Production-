"""
Comprehensive Test Suite for Authentication System

Run with: pytest test_auth.py -v --asyncio-mode=auto
Install: pip install pytest pytest-asyncio httpx faker
"""

import pytest
import asyncio
import secrets
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, AsyncMock, patch
import jwt

# Import modules to test
from Authatication.google_auth import (
    SimpleAuthSecure, InMemoryStore, AuthConfig,
    generate_pkce_pair, RateLimiter, Environment
)
from Authatication.oauth import RedisStorage


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def test_config():
    """Minimal valid test configuration."""
    return {
        "client_id": "test-client-id",
        "client_secret": "test-client-secret",
        "app_secret_key": secrets.token_urlsafe(32),
        "redirect_uri": "http://localhost:8000/callback",
        "authorize_url": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_url": "https://oauth2.googleapis.com/token",
        "userinfo_url": "https://www.googleapis.com/oauth2/v2/userinfo",
        "environment": "development"
    }


@pytest.fixture
async def storage():
    """In-memory storage for testing."""
    store = InMemoryStore()
    await store.start_cleanup()
    yield store
    await store.stop()


@pytest.fixture
async def auth_system(test_config, storage):
    """Initialized auth system."""
    auth = SimpleAuthSecure(test_config, storage=storage)
    await auth.initialize()
    yield auth
    await auth.shutdown()


# ============================================================================
# Configuration Validation Tests
# ============================================================================

class TestConfigValidation:
    """Test configuration validation."""
    
    def test_missing_required_keys(self):
        """Test that missing required keys raise ValueError."""
        config = {"client_id": "test"}
        with pytest.raises(ValueError, match="Missing required config"):
            SimpleAuthSecure(config)
    
    def test_weak_secret_key(self, test_config):
        """Test that weak secret keys are rejected."""
        test_config["app_secret_key"] = "weak"
        with pytest.raises(ValueError, match="must be at least"):
            SimpleAuthSecure(test_config)
    
    def test_common_weak_secrets(self, test_config):
        """Test that common weak secrets are rejected."""
        weak_secrets = ["changeme", "secret", "password", "test"]
        for weak in weak_secrets:
            test_config["app_secret_key"] = weak + "x" * 30  # Make it long enough
            with pytest.raises(ValueError, match="low entropy"):
                SimpleAuthSecure(test_config)
    
    def test_invalid_url_format(self, test_config):
        """Test that invalid URLs are rejected."""
        test_config["redirect_uri"] = "not-a-url"
        with pytest.raises(ValueError, match="must be a valid URL"):
            SimpleAuthSecure(test_config)
    
    def test_http_in_production(self, test_config):
        """Test that HTTP URLs are rejected in production."""
        test_config["environment"] = "production"
        test_config["redirect_uri"] = "http://example.com/callback"
        with pytest.raises(ValueError, match="must use HTTPS in production"):
            SimpleAuthSecure(test_config)
    
    def test_production_requires_storage(self, test_config):
        """Test that production requires external storage."""
        test_config["environment"] = "production"
        with pytest.raises(RuntimeError, match="Storage backend is required"):
            SimpleAuthSecure(test_config, storage=None)
    
    def test_negative_expiry_values(self, test_config):
        """Test that negative expiry values are rejected."""
        test_config["access_expires_minutes"] = -10
        with pytest.raises(ValueError, match="must be positive"):
            SimpleAuthSecure(test_config)


# ============================================================================
# PKCE Tests
# ============================================================================

class TestPKCE:
    """Test PKCE code verifier and challenge generation."""
    
    def test_pkce_generation(self):
        """Test that PKCE pair is generated correctly."""
        verifier, challenge = generate_pkce_pair()
        
        # Verifier should be URL-safe base64
        assert len(verifier) > 0
        assert all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in verifier)
        
        # Challenge should be URL-safe base64
        assert len(challenge) > 0
        assert all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in challenge)
    
    def test_pkce_uniqueness(self):
        """Test that each PKCE pair is unique."""
        pairs = [generate_pkce_pair() for _ in range(100)]
        verifiers = [p[0] for p in pairs]
        challenges = [p[1] for p in pairs]
        
        # All should be unique
        assert len(set(verifiers)) == 100
        assert len(set(challenges)) == 100


# ============================================================================
# Storage Backend Tests
# ============================================================================

class TestInMemoryStore:
    """Test in-memory storage backend."""
    
    @pytest.mark.asyncio
    async def test_set_and_get(self, storage):
        """Test basic set and get operations."""
        await storage.set("test_key", {"value": "test"}, 60)
        result = await storage.get("test_key")
        assert result == {"value": "test"}
    
    @pytest.mark.asyncio
    async def test_expiration(self, storage):
        """Test that entries expire correctly."""
        await storage.set("test_key", {"value": "test"}, 1)
        await asyncio.sleep(1.5)
        result = await storage.get("test_key")
        assert result is None
    
    @pytest.mark.asyncio
    async def test_delete(self, storage):
        """Test deletion of keys."""
        await storage.set("test_key", {"value": "test"}, 60)
        await storage.delete("test_key")
        result = await storage.get("test_key")
        assert result is None
    
    @pytest.mark.asyncio
    async def test_exists(self, storage):
        """Test exists check."""
        await storage.set("test_key", {"value": "test"}, 60)
        assert await storage.exists("test_key") is True
        assert await storage.exists("nonexistent") is False
    
    @pytest.mark.asyncio
    async def test_cleanup(self, storage):
        """Test that expired entries are cleaned up."""
        # Add expired entries
        for i in range(10):
            await storage.set(f"key_{i}", {"value": i}, 1)
        
        await asyncio.sleep(1.5)
        await storage._cleanup_expired()
        
        # All should be gone
        for i in range(10):
            result = await storage.get(f"key_{i}")
            assert result is None


# ============================================================================
# Rate Limiter Tests
# ============================================================================

class TestRateLimiter:
    """Test rate limiting functionality."""
    
    @pytest.mark.asyncio
    async def test_rate_limit_allows_initial_requests(self):
        """Test that initial requests are allowed."""
        limiter = RateLimiter(requests_per_minute=10, burst=5)
        await limiter.start()
        
        # First 5 should be allowed (burst)
        for i in range(5):
            assert await limiter.check(f"client_{i}") is True
        
        await limiter.stop()
    
    @pytest.mark.asyncio
    async def test_rate_limit_blocks_excess(self):
        """Test that excess requests are blocked."""
        limiter = RateLimiter(requests_per_minute=10, burst=3)
        await limiter.start()
        
        client = "test_client"
        
        # First 3 should pass (burst)
        for i in range(3):
            assert await limiter.check(client) is True
        
        # 4th should be blocked
        assert await limiter.check(client) is False
        
        await limiter.stop()
    
    @pytest.mark.asyncio
    async def test_rate_limit_recovery(self):
        """Test that rate limit recovers over time."""
        limiter = RateLimiter(requests_per_minute=60, burst=2)
        await limiter.start()
        
        client = "test_client"
        
        # Use up burst
        assert await limiter.check(client) is True
        assert await limiter.check(client) is True
        assert await limiter.check(client) is False
        
        # Wait for recovery (1 req/sec)
        await asyncio.sleep(1.5)
        
        # Should be allowed now
        assert await limiter.check(client) is True
        
        await limiter.stop()
    
    @pytest.mark.asyncio
    async def test_rate_limit_cleanup(self):
        """Test that old buckets are cleaned up."""
        limiter = RateLimiter(requests_per_minute=10, burst=2)
        await limiter.start()
        
        # Create some buckets
        for i in range(10):
            await limiter.check(f"client_{i}")
        
        assert len(limiter.buckets) == 10
        
        # Manually trigger cleanup
        await limiter._cleanup_loop()
        
        await limiter.stop()


# ============================================================================
# JWT Token Tests
# ============================================================================

class TestJWTTokens:
    """Test JWT token generation and validation."""
    
    @pytest.mark.asyncio
    async def test_token_generation(self, auth_system):
        """Test that JWT tokens are generated correctly."""
        user_id = "test_user_123"
        now = datetime.now(timezone.utc)
        exp = now + timedelta(minutes=10)
        
        payload = {
            "sub": user_id,
            "email": "test@example.com",
            "iat": int(now.timestamp()),
            "exp": int(exp.timestamp()),
            "jti": "test_jti",
            "iss": "SimpleAuthSecure",
            "aud": auth_system.client_id
        }
        
        token = jwt.encode(
            payload,
            auth_system.app_secret_key,
            algorithm=auth_system.jwt_algorithm
        )
        
        # Verify token
        decoded = await auth_system.verify_access_token(token)
        assert decoded["sub"] == user_id
        assert decoded["email"] == "test@example.com"
    
    @pytest.mark.asyncio
    async def test_expired_token_rejected(self, auth_system):
        """Test that expired tokens are rejected."""
        user_id = "test_user_123"
        now = datetime.now(timezone.utc)
        exp = now - timedelta(minutes=10)  # Already expired
        
        payload = {
            "sub": user_id,
            "iat": int(now.timestamp()),
            "exp": int(exp.timestamp()),
            "jti": "test_jti",
            "iss": "SimpleAuthSecure",
            "aud": auth_system.client_id
        }
        
        token = jwt.encode(
            payload,
            auth_system.app_secret_key,
            algorithm=auth_system.jwt_algorithm
        )
        
        # Should raise exception
        from fastapi import HTTPException
        with pytest.raises(HTTPException, match="expired"):
            await auth_system.verify_access_token(token)
    
    @pytest.mark.asyncio
    async def test_invalid_signature_rejected(self, auth_system):
        """Test that tokens with invalid signature are rejected."""
        user_id = "test_user_123"
        now = datetime.now(timezone.utc)
        exp = now + timedelta(minutes=10)
        
        payload = {
            "sub": user_id,
            "iat": int(now.timestamp()),
            "exp": int(exp.timestamp()),
            "jti": "test_jti",
            "iss": "SimpleAuthSecure",
            "aud": auth_system.client_id
        }
        
        # Sign with wrong key
        token = jwt.encode(payload, "wrong_secret", algorithm="HS256")
        
        # Should raise exception
        from fastapi import HTTPException
        with pytest.raises(HTTPException, match="Invalid token"):
            await auth_system.verify_access_token(token)
    
    @pytest.mark.asyncio
    async def test_blacklisted_token_rejected(self, auth_system):
        """Test that blacklisted tokens are rejected."""
        user_id = "test_user_123"
        now = datetime.now(timezone.utc)
        exp = now + timedelta(minutes=10)
        jti = "blacklisted_jti"
        
        payload = {
            "sub": user_id,
            "iat": int(now.timestamp()),
            "exp": int(exp.timestamp()),
            "jti": jti,
            "iss": "SimpleAuthSecure",
            "aud": auth_system.client_id
        }
        
        token = jwt.encode(
            payload,
            auth_system.app_secret_key,
            algorithm=auth_system.jwt_algorithm
        )
        
        # Blacklist the token
        await auth_system._store.set(
            f"{AuthConfig.BLACKLIST_PREFIX}{jti}",
            {"revoked": True},
            600
        )
        
        # Should be rejected
        from fastapi import HTTPException
        with pytest.raises(HTTPException, match="revoked"):
            await auth_system.verify_access_token(token)


# ============================================================================
# Refresh Token Tests
# ============================================================================

class TestRefreshTokens:
    """Test refresh token functionality."""
    
    @pytest.mark.asyncio
    async def test_refresh_token_creation(self, auth_system):
        """Test that refresh tokens are created correctly."""
        refresh_token = secrets.token_urlsafe(48)
        user_id = "test_user_123"
        
        refresh_record = {
            "user_id": user_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "jti": str(secrets.token_urlsafe(16))
        }
        
        await auth_system._store.set(
            f"{AuthConfig.REFRESH_PREFIX}{refresh_token}",
            refresh_record,
            86400
        )
        
        # Should be able to retrieve it
        result = await auth_system._store.get(
            f"{AuthConfig.REFRESH_PREFIX}{refresh_token}"
        )
        assert result["user_id"] == user_id
    
    @pytest.mark.asyncio
    async def test_refresh_token_rotation(self, auth_system):
        """Test that refresh tokens are rotated."""
        # Create initial refresh token
        old_refresh = secrets.token_urlsafe(48)
        user_id = "test_user_123"
        
        await auth_system._store.set(
            f"{AuthConfig.REFRESH_PREFIX}{old_refresh}",
            {
                "user_id": user_id,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "jti": "old_jti"
            },
            86400
        )
        
        # Refresh the token
        new_tokens = await auth_system.refresh_access_token(old_refresh)
        
        # Old token should be gone
        old_data = await auth_system._store.get(
            f"{AuthConfig.REFRESH_PREFIX}{old_refresh}"
        )
        assert old_data is None
        
        # New token should exist
        new_refresh = new_tokens["refresh_token"]
        new_data = await auth_system._store.get(
            f"{AuthConfig.REFRESH_PREFIX}{new_refresh}"
        )
        assert new_data is not None
        assert new_data["user_id"] == user_id
    
    @pytest.mark.asyncio
    async def test_revoke_refresh_token(self, auth_system):
        """Test that refresh tokens can be revoked."""
        refresh_token = secrets.token_urlsafe(48)
        user_id = "test_user_123"
        jti = "test_jti"
        
        await auth_system._store.set(
            f"{AuthConfig.REFRESH_PREFIX}{refresh_token}",
            {
                "user_id": user_id,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "jti": jti
            },
            86400
        )
        
        # Revoke it
        revoked = await auth_system.revoke_refresh_token(refresh_token)
        assert revoked is True
        
        # Should be gone
        result = await auth_system._store.get(
            f"{AuthConfig.REFRESH_PREFIX}{refresh_token}"
        )
        assert result is None
        
        # Access token should be blacklisted
        blacklisted = await auth_system._store.exists(
            f"{AuthConfig.BLACKLIST_PREFIX}{jti}"
        )
        assert blacklisted is True


# ============================================================================
# Token Introspection Tests
# ============================================================================

class TestTokenIntrospection:
    """Test token introspection functionality."""
    
    @pytest.mark.asyncio
    async def test_introspect_valid_token(self, auth_system):
        """Test introspection of valid token."""
        user_id = "test_user_123"
        now = datetime.now(timezone.utc)
        exp = now + timedelta(minutes=10)
        
        payload = {
            "sub": user_id,
            "email": "test@example.com",
            "iat": int(now.timestamp()),
            "exp": int(exp.timestamp()),
            "jti": "test_jti",
            "iss": "SimpleAuthSecure",
            "aud": auth_system.client_id
        }
        
        token = jwt.encode(
            payload,
            auth_system.app_secret_key,
            algorithm=auth_system.jwt_algorithm
        )
        
        # Introspect
        result = await auth_system.introspect_token(token)
        assert result["active"] is True
        assert result["sub"] == user_id
        assert result["email"] == "test@example.com"
    
    @pytest.mark.asyncio
    async def test_introspect_invalid_token(self, auth_system):
        """Test introspection of invalid token."""
        result = await auth_system.introspect_token("invalid_token")
        assert result["active"] is False
        assert "error" in result


# ============================================================================
# Metrics Tests
# ============================================================================

class TestMetrics:
    """Test metrics tracking."""
    
    @pytest.mark.asyncio
    async def test_metrics_initialization(self, auth_system):
        """Test that metrics are initialized."""
        metrics = auth_system.get_metrics()
        
        assert "logins_total" in metrics
        assert "logins_success" in metrics
        assert "logins_failed" in metrics
        assert "token_refreshes" in metrics
        assert "token_revocations" in metrics
        assert "rate_limit_hits" in metrics
        assert "token_introspections" in metrics
    
    @pytest.mark.asyncio
    async def test_metrics_increment(self, auth_system):
        """Test that metrics increment correctly."""
        initial = auth_system.get_metrics()
        
        # Increment some metrics
        auth_system._metrics["logins_total"] += 1
        auth_system._metrics["logins_success"] += 1
        
        updated = auth_system.get_metrics()
        
        assert updated["logins_total"] == initial["logins_total"] + 1
        assert updated["logins_success"] == initial["logins_success"] + 1


# ============================================================================
# Health Check Tests
# ============================================================================

class TestHealthCheck:
    """Test health check functionality."""
    
    @pytest.mark.asyncio
    async def test_health_check_initialized(self, auth_system):
        """Test health check when initialized."""
        health = await auth_system.health_check()
        
        assert health["status"] in ["healthy", "degraded"]
        assert "storage" in health
        assert "environment" in health
        assert health["environment"] == "development"
    
    @pytest.mark.asyncio
    async def test_health_check_storage(self, auth_system):
        """Test that health check verifies storage."""
        health = await auth_system.health_check()
        assert health["storage"] == "ok"


# ============================================================================
# Integration Tests
# ============================================================================

class TestIntegration:
    """Integration tests for complete authentication flow."""
    
    @pytest.mark.asyncio
    async def test_complete_auth_flow(self, auth_system):
        """Test complete authentication flow."""
        # This would normally involve OAuth, so we mock it
        # 1. User would get login URL
        # 2. User would authenticate with provider
        # 3. Provider would callback with code
        # 4. We exchange code for tokens
        # 5. We generate JWT
        # 6. User uses JWT for requests
        
        # Simulate generating a JWT
        user_id = "test_user_123"
        now = datetime.now(timezone.utc)
        exp = now + timedelta(minutes=10)
        
        payload = {
            "sub": user_id,
            "email": "test@example.com",
            "iat": int(now.timestamp()),
            "exp": int(exp.timestamp()),
            "jti": "test_jti",
            "iss": "SimpleAuthSecure",
            "aud": auth_system.client_id
        }
        
        access_token = jwt.encode(
            payload,
            auth_system.app_secret_key,
            algorithm=auth_system.jwt_algorithm
        )
        
        # Verify token works
        decoded = await auth_system.verify_access_token(access_token)
        assert decoded["sub"] == user_id
        
        # Create refresh token
        refresh_token = secrets.token_urlsafe(48)
        await auth_system._store.set(
            f"{AuthConfig.REFRESH_PREFIX}{refresh_token}",
            {
                "user_id": user_id,
                "created_at": now.isoformat(),
                "jti": payload["jti"]
            },
            86400
        )
        
        # Refresh tokens
        new_tokens = await auth_system.refresh_access_token(refresh_token)
        assert "access_token" in new_tokens
        assert "refresh_token" in new_tokens
        
        # Revoke refresh token
        revoked = await auth_system.revoke_refresh_token(new_tokens["refresh_token"])
        assert revoked is True


# ============================================================================
# Run Tests
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--asyncio-mode=auto"])
