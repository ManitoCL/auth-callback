/**
 * Supabase Auth Webhook Handler - Device-Agnostic Email Verification
 * Receives webhooks when users verify emails, stores verification events
 * Enables device-agnostic email extraction for verified.js
 */

const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');

// Initialize Supabase admin client
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

// Webhook secret for security
const WEBHOOK_SECRET = process.env.SUPABASE_WEBHOOK_SECRET || 'your-webhook-secret-here';

module.exports = async function handler(req, res) {
  // Only allow POST requests
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    // Verify webhook signature for security
    const signature = req.headers['x-webhook-signature'] || req.headers['webhook-signature'];
    const body = JSON.stringify(req.body);

    if (signature && WEBHOOK_SECRET !== 'your-webhook-secret-here') {
      const expectedSignature = crypto
        .createHmac('sha256', WEBHOOK_SECRET)
        .update(body)
        .digest('hex');

      if (signature !== expectedSignature) {
        console.error('❌ Invalid webhook signature');
        return res.status(401).json({ error: 'Invalid signature' });
      }
    }

    const event = req.body;
    console.log('🔗 Webhook received:', {
      type: event.type,
      userId: event.record?.id,
      email: event.record?.email,
      emailConfirmedAt: event.record?.email_confirmed_at
    });

    // Handle email verification events
    if (event.type === 'UPDATE' && event.table === 'users') {
      const user = event.record;
      const oldUser = event.old_record;

      // Check if email was just verified (email_confirmed_at changed from null to a value)
      if (!oldUser?.email_confirmed_at && user?.email_confirmed_at && user?.email) {
        console.log('✅ Email verification detected for user:', user.email);

        // Store verification event for device-agnostic retrieval
        const verificationEvent = {
          user_id: user.id,
          user_email: user.email,
          verified_at: user.email_confirmed_at,
          event_type: 'email_verified',
          metadata: {
            user_type: user.user_metadata?.user_type || 'customer',
            full_name: user.user_metadata?.full_name || user.email.split('@')[0],
            verification_method: 'email_link'
          },
          expires_at: new Date(Date.now() + 15 * 60 * 1000).toISOString() // 15 minute expiry
        };

        // Store in verification_events table
        const { error: insertError } = await supabase
          .from('verification_events')
          .insert(verificationEvent);

        if (insertError) {
          console.error('❌ Failed to store verification event:', insertError);
        } else {
          console.log('📝 Verification event stored successfully');
        }

        // OPTIONAL: Clean up old verification events (older than 1 hour)
        await supabase
          .from('verification_events')
          .delete()
          .lt('created_at', new Date(Date.now() - 60 * 60 * 1000).toISOString());
      }
    }

    // Handle auth.user.updated events (alternative webhook format)
    if (event.type === 'auth.user.updated' && event.user) {
      const user = event.user;

      if (user.email_confirmed_at && user.email) {
        console.log('✅ Auth webhook: Email verification for user:', user.email);

        const verificationEvent = {
          user_id: user.id,
          user_email: user.email,
          verified_at: user.email_confirmed_at,
          event_type: 'email_verified_auth_webhook',
          metadata: {
            user_type: user.user_metadata?.user_type || 'customer',
            full_name: user.user_metadata?.full_name || user.email.split('@')[0],
            verification_method: 'auth_webhook'
          },
          expires_at: new Date(Date.now() + 15 * 60 * 1000).toISOString()
        };

        const { error: insertError } = await supabase
          .from('verification_events')
          .insert(verificationEvent);

        if (insertError) {
          console.error('❌ Failed to store auth verification event:', insertError);
        } else {
          console.log('📝 Auth verification event stored successfully');
        }
      }
    }

    res.status(200).json({
      success: true,
      message: 'Webhook processed successfully',
      eventType: event.type
    });

  } catch (error) {
    console.error('❌ Webhook processing error:', error);
    res.status(500).json({
      error: 'Internal server error',
      message: error.message
    });
  }
};