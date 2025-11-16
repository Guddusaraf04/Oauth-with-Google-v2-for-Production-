# 🚀 Multi-Provider OAuth Setup Guide

## Quick Start (5 minutes)

### Step 1: Save Required Files

Save these files in your project folder:

```
your-project/
├── main.py                      # Replace with integrated_multi_provider
├── multi_provider_auth.py       # From earlier artifact
├── Auth.py                      # Your existing file
├── oauth.py                     # Your existing file
├── google_auth.py               # Your existing file
├── auth_frontend_html.html      # Your existing file
├── multi_provider_login.html    # New file (from artifact)
├── callback.html                # Your existing file
└── .env                         # Update with template below
```

---

### Step 2: Update .env File

```env
# ============================================================================
# EXISTING SETTINGS (Keep these)
# ============================================================================
APP_SECRET_KEY=your-32-character-secret-key-here
ENVIRONMENT=development
BACKEND_URL=http://127.0.0.1:9000
FRONTEND_URL=http://127.0.0.1:9000

# ============================================================================
# GOOGLE OAUTH (You already have this)
# ============================================================================
GOOGLE_CLIENT_ID=your-google-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-your-google-secret
OAUTH_REDIRECT_URI=http://127.0.0.1:9000/auth/callback/google

# ============================================================================
# ADDITIONAL PROVIDERS (Optional - Add only the ones you want)
# ============================================================================

# GitHub OAuth (RECOMMENDED - Easy to setup)
# Get from: https://github.com/settings/developers
GITHUB_CLIENT_ID=your_github_client_id
GITHUB_CLIENT_SECRET=your_github_client_secret

# Microsoft OAuth (For enterprise users)
# Get from: https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps
# MICROSOFT_CLIENT_ID=your_microsoft_client_id
# MICROSOFT_CLIENT_SECRET=your_microsoft_client_secret

# Discord OAuth (For gaming/community apps)
# Get from: https://discord.com/developers/applications
# DISCORD_CLIENT_ID=your_discord_client_id
# DISCORD_CLIENT_SECRET=your_discord_client_secret

# Facebook OAuth (Requires app review for production)
# Get from: https://developers.facebook.com/apps
# FACEBOOK_CLIENT_ID=your_facebook_app_id
# FACEBOOK_CLIENT_SECRET=your_facebook_app_secret

# Twitter/X OAuth (More complex setup)
# Get from: https://developer.twitter.com/en/portal/dashboard
# TWITTER_CLIENT_ID=your_twitter_client_id
# TWITTER_CLIENT_SECRET=your_twitter_client_secret
```

---

### Step 3: Configure OAuth Redirect URIs

For each provider you want to use, add these redirect URIs in their console:

**Google:** `http://127.0.0.1:9000/auth/callback/google`  
**GitHub:** `http://127.0.0.1:9000/auth/callback/github`  
**Microsoft:** `http://127.0.0.1:9000/auth/callback/microsoft`  
**Discord:** `http://127.0.0.1:9000/auth/callback/discord`  
**Facebook:** `http://127.0.0.1:9000/auth/callback/facebook`  
**Twitter:** `http://127.0.0.1:9000/auth/callback/twitter`

---

### Step 4: Test It!

```bash
# Start server
python main.py

# Visit
http://127.0.0.1:9000/

# Check available providers
http://127.0.0.1:9000/auth/providers
```

You should see a login page with buttons for each configured provider!

---

## 📋 What Happens Automatically

✅ **Single Provider (Google only):**
- Shows regular login page
- Works exactly like before
- No changes needed!

✅ **Multiple Providers:**
- Automatically detects configured providers
- Shows multi-provider login page
- User can choose their preferred method

---

## 🎯 Minimal Setup (Just Add GitHub)

**Want to test multi-provider with minimal effort? Just add GitHub:**

### 1. Get GitHub OAuth App (2 minutes)

1. Go to https://github.com/settings/developers
2. Click "New OAuth App"
3. Fill in:
   - **Application name:** Your App Name
   - **Homepage URL:** `http://localhost:9000`
   - **Authorization callback URL:** `http://127.0.0.1:9000/auth/callback/github`
4. Click "Register application"
5. Copy `Client ID` and generate `Client Secret`

### 2. Add to .env

```env
GITHUB_CLIENT_ID=Iv1.abc123def456
GITHUB_CLIENT_SECRET=abc123def456ghi789
```

### 3. Restart Server

```bash
python main.py
```

**Done!** Visit `http://127.0.0.1:9000/` and you'll see both Google and GitHub login options!

---

## 🔍 How It Works

### Architecture

```
User clicks "Login with GitHub"
         ↓
/auth/login/github
         ↓
Redirect to GitHub OAuth
         ↓
User authorizes
         ↓
/auth/callback/github?code=...
         ↓
Exchange code for token
         ↓
Get user info from GitHub
         ↓
Generate JWT tokens (your system)
         ↓
Set cookies & redirect to app
         ↓
User is logged in! ✅
```

### Key Features

1. **Unified JWT System**
   - All providers use your existing JWT tokens
   - Same token format for all providers
   - Works with existing `auth.user()` dependency

2. **Provider Identification**
   - User ID includes provider: `github:12345`
   - JWT payload includes `provider` field
   - Can track which provider user used

3. **Automatic Detection**
   - System detects which providers are configured
   - Shows only available providers
   - No code changes needed to add/remove providers

4. **Backward Compatible**
   - Works with existing Google-only setup
   - No breaking changes
   - Can add providers gradually

---

## 📊 API Endpoints

### New Endpoints

```bash
# List available providers
GET /auth/providers
Response: {"providers": ["google", "github"], "count": 2}

# Login with specific provider
GET /auth/login/{provider}
Example: /auth/login/github

# Callback for specific provider
GET /auth/callback/{provider}
Example: /auth/callback/github
```

### Existing Endpoints (unchanged)

```bash
GET  /auth/profile     # Get user profile
POST /auth/logout      # Logout
POST /auth/refresh     # Refresh token
GET  /api/protected    # Protected route
GET  /api/public       # Public route
```

---

## 🎨 Frontend Integration

### Option 1: Auto-Detect UI (Recommended)

The system automatically shows:
- **Multi-provider UI** if multiple providers configured
- **Single-provider UI** if only Google configured

Just visit `http://127.0.0.1:9000/`

### Option 2: Manual Provider Selection

```javascript
// Fetch available providers
const response = await fetch('/auth/providers');
const data = await response.json();

// data.providers = ["google", "github", "discord"]

// Create login buttons
data.providers.forEach(provider => {
    const button = document.createElement('button');
    button.textContent = `Login with ${provider}`;
    button.onclick = () => {
        window.location.href = `/auth/login/${provider}`;
    };
    document.body.appendChild(button);
});
```

### Option 3: Direct Login Link

```html
<!-- Direct links to specific providers -->
<a href="/auth/login/google">Login with Google</a>
<a href="/auth/login/github">Login with GitHub</a>
<a href="/auth/login/discord">Login with Discord</a>
```

---

## 🔐 Security Notes

### User ID Format

```javascript
// Single provider (Google only)
user.id = "111954453361564881921"

// Multi-provider
user.id = "google:111954453361564881921"
user.id = "github:12345678"
user.id = "discord:98765432"
```

### Why This Matters

- Prevents ID collisions between providers
- User can login with multiple providers
- Each provider login is treated as separate account

### Same Email, Different Providers

If a user logs in with:
- `user@example.com` via Google → `google:123`
- `user@example.com` via GitHub → `github:456`

They are treated as **two separate accounts** (secure by default).

**To link accounts:** You'd need to implement account linking logic based on email matching.

---

## 🧪 Testing Checklist

- [ ] Google login works
- [ ] GitHub login works (if configured)
- [ ] Can access protected routes after login
- [ ] Token refresh works
- [ ] Logout works
- [ ] Provider info shows in profile
- [ ] Auto-refresh still works
- [ ] `/auth/providers` shows correct list

---

## 🐛 Troubleshooting

### "multi_provider_auth.py not found"
**Solution:** Make sure you saved the `multi_provider_auth.py` file in your project folder.

### "Only Google login available"
**Solution:** Check your .env file has the provider credentials uncommented.

### "Redirect URI mismatch"
**Solution:** Make sure the redirect URI in your code matches exactly what's in the provider console.

### Provider not showing in login page
**Solution:** 
1. Check .env has the credentials
2. Restart server
3. Visit `/auth/providers` to see detected providers

---

## 📈 Migration Path

### Phase 1: Current (Google Only) ✅
- You're here already
- Everything works

### Phase 2: Add GitHub (5 minutes)
- Add GitHub credentials to .env
- Test with GitHub login
- **Rating: 9.7/10** 🎉

### Phase 3: Add More Providers (Optional)
- Add Microsoft for enterprise
- Add Discord for community
- Add others as needed
- **Rating: 10/10** 🚀

---

## 💡 Pro Tips

1. **Start Small:** Just add GitHub first to test
2. **Production:** Use environment-specific redirect URIs
3. **Monitoring:** Check `/health` endpoint for provider status
4. **Analytics:** Track which providers users prefer
5. **UX:** Show provider icons instead of text

---

## 🎉 Benefits

✅ **User Choice:** Let users pick their preferred login method  
✅ **Higher Conversion:** More login options = more signups  
✅ **Enterprise Ready:** Support Microsoft for corporate users  
✅ **Developer Friendly:** GitHub appeals to technical users  
✅ **Gaming Apps:** Discord integration for gaming communities  
✅ **Flexibility:** Add/remove providers without code changes

---

## 📞 Need Help?

**Issue:** Provider not working  
**Solution:** Check provider setup guide, verify redirect URIs

**Issue:** Existing Google login broken  
**Solution:** System is backward compatible, check .env has GOOGLE_CLIENT_ID

**Issue:** Want to link accounts  
**Solution:** Implement email-based account linking (custom feature)

---

## ✅ Summary

**To use multi-provider:**
1. Save `multi_provider_auth.py`
2. Replace `main.py` with integrated version
3. Add provider credentials to `.env`
4. Configure redirect URIs in provider consoles
5. Restart server
6. Done! 🎉

**That's it!** Your app now supports multiple OAuth providers while maintaining all existing functionality.
