# Manito Enterprise Auth Callback

## Overview
Authentication callback service for the Manito mobile app's Enterprise Redux workflow. Handles PKCE email verification and generates deep links compatible with the new Redux-based authentication system.

## Enterprise Redux Integration
This service has been updated to work with Manito's new enterprise authentication architecture:
- Redux Toolkit state management
- RTK Query server state caching
- Enterprise auth middleware
- Background profile creation via `enterpriseProfileService.ts`

## Solution
PKCE email verification flow with Enterprise Redux compatibility:

1. **New API Endpoint**: `/api/verify-email.js` handles the `?code=xxx` parameter
2. **Code Exchange**: Exchanges the verification code for session tokens using Supabase
3. **Secure Session**: Creates a secure session code for mobile app deep linking
4. **Frontend Update**: Updated `index.html` to handle both secure session codes and direct tokens

## Enterprise Redux Flow
1. User clicks email verification link → `https://auth.manito.cl/verify?code=abc123`
2. `/api/verify-email.js` validates the code with Supabase using PKCE
3. Exchanges code for session tokens
4. Frontend generates deep link with Redux-compatible parameters
5. Redirects to mobile app: `exp://localhost:8082/--/auth/callback?access_token=xxx&auth_method=email&flow_type=pkce&verified=true`
6. Mobile app's Enterprise auth middleware processes the deep link
7. Profile creation handled by `enterpriseProfileService.ts` with retry logic

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
