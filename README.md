# Manito Email Verification Fix

## Problem
The Vercel edge function at https://auth.manito.cl was showing "Acceso no autorizado" error when handling email verification codes from Supabase.

## Root Cause
The previous implementation expected Supabase to redirect with tokens directly in the URL hash, but Supabase email verification actually sends a `code` parameter that needs to be exchanged for tokens server-side.

## Solution
Created a proper email verification flow:

1. **New API Endpoint**: `/api/verify-email.js` handles the `?code=xxx` parameter
2. **Code Exchange**: Exchanges the verification code for session tokens using Supabase
3. **Secure Session**: Creates a secure session code for mobile app deep linking
4. **Frontend Update**: Updated `index.html` to handle both secure session codes and direct tokens

## Flow
1. User clicks email verification link → `https://auth.manito.cl/verify?code=abc123`
2. `/api/verify-email.js` validates the code with Supabase
3. Exchanges code for session tokens
4. Creates secure session code
5. Redirects to frontend with session code: `/?session_code=xyz789`
6. Frontend retrieves tokens from session code and redirects to app: `manito://auth/callback`

## Files Modified
- `api/verify-email.js` - New email verification handler
- `vercel.json` - Added `/verify` route
- `public/index.html` - Updated to handle session codes
- `package.json` - Added @supabase/supabase-js dependency
- `.env.example` - Environment variables documentation

## Environment Variables
Add these to your Vercel project:
- `SUPABASE_URL` - Your Supabase project URL
- `SUPABASE_ANON_KEY` - Supabase anonymous key
- `SUPABASE_SERVICE_ROLE_KEY` - Service role key for profile creation

## Supabase Configuration
Update your Supabase Auth settings:
- Site URL: `https://auth.manito.cl/verify`
- Redirect URLs: `https://auth.manito.cl/verify`

## Testing
1. Sign up new user in Manito app
2. Check email for verification link
3. Click verification link
4. Should redirect to `https://auth.manito.cl/verify?code=xxx`
5. Should process verification and redirect to app successfully

## Deployment
```bash
npm install
vercel --prod
```
