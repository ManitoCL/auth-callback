# Manito Auth Callback

Email confirmation callback handler for the Manito mobile app.

## Deployment to Vercel

1. **Install Vercel CLI** (if not already installed):
   ```bash
   npm install -g vercel
   ```

2. **Deploy to Vercel**:
   ```bash
   cd C:\Users\night\Manito\auth-callback
   vercel
   ```
   - Follow the prompts
   - Choose your Vercel account
   - Set project name: `manito-auth-callback`

3. **Set up custom domain**:
   - In Vercel dashboard, go to your project
   - Go to Settings > Domains
   - Add domain: `auth.manito.cl`
   - Update your DNS (in Cloudflare):
     - Add CNAME record: `auth` pointing to your Vercel project URL

4. **Update Supabase URLs**:
   - In Supabase dashboard > Authentication > URL Configuration
   - Set redirect URLs to: `https://auth.manito.cl`

## Local Development

```bash
vercel dev
```

## Configuration

Update the Supabase credentials in `index.html` if needed (they should already be correct).