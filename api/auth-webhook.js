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

        // ENHANCED DEBUG: Deep metadata analysis for user type extraction
        console.log('🐛 Debug: Full user object received by webhook:', JSON.stringify(user, null, 2));
        console.log('🐛 Debug: User metadata specifically:', user.user_metadata);
        console.log('🐛 Debug: Raw metadata specifically:', user.raw_user_meta_data);
        console.log('🐛 Debug: App metadata specifically:', user.app_metadata);

        // IMPROVED USER TYPE EXTRACTION: Try multiple metadata sources
        let extractedUserType = 'customer'; // Default fallback

        // Method 1: Check user_metadata (primary)
        if (user.user_metadata?.user_type) {
          extractedUserType = user.user_metadata.user_type;
          console.log('✅ User type from user_metadata:', extractedUserType);
        }
        // Method 2: Check raw_user_meta_data (alternative)
        else if (user.raw_user_meta_data?.user_type) {
          extractedUserType = user.raw_user_meta_data.user_type;
          console.log('✅ User type from raw_user_meta_data:', extractedUserType);
        }
        // Method 3: Check app_metadata (admin set)
        else if (user.app_metadata?.user_type) {
          extractedUserType = user.app_metadata.user_type;
          console.log('✅ User type from app_metadata:', extractedUserType);
        }
        // Method 4: Query database for user_type (fallback)
        else {
          console.log('⚠️ No user_type in metadata, querying database...');
          try {
            const { data: dbUser, error } = await supabase
              .from('users')
              .select('user_type')
              .eq('id', user.id)
              .single();

            if (!error && dbUser?.user_type) {
              extractedUserType = dbUser.user_type;
              console.log('✅ User type from database query:', extractedUserType);
            }
          } catch (queryError) {
            console.log('⚠️ Database query failed, using default:', queryError.message);
          }
        }

        console.log('🎯 Final extracted user_type:', extractedUserType);

        // Store verification event for device-agnostic retrieval
        const verificationEvent = {
          user_id: user.id,
          user_email: user.email,
          verified_at: user.email_confirmed_at,
          event_type: 'email_verified',
          metadata: {
            user_type: extractedUserType,
            full_name: user.user_metadata?.full_name || user.raw_user_meta_data?.full_name || user.email.split('@')[0],
            verification_method: 'email_link',
            metadata_sources_checked: {
              user_metadata: !!user.user_metadata?.user_type,
              raw_user_meta_data: !!user.raw_user_meta_data?.user_type,
              app_metadata: !!user.app_metadata?.user_type,
              database_query: extractedUserType !== 'customer' || (!user.user_metadata?.user_type && !user.raw_user_meta_data?.user_type && !user.app_metadata?.user_type)
            }
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

        // IMPROVED USER TYPE EXTRACTION: Try multiple metadata sources (same as above)
        let extractedUserType = 'customer'; // Default fallback

        // Method 1: Check user_metadata (primary)
        if (user.user_metadata?.user_type) {
          extractedUserType = user.user_metadata.user_type;
          console.log('✅ Auth webhook user type from user_metadata:', extractedUserType);
        }
        // Method 2: Check raw_user_meta_data (alternative)
        else if (user.raw_user_meta_data?.user_type) {
          extractedUserType = user.raw_user_meta_data.user_type;
          console.log('✅ Auth webhook user type from raw_user_meta_data:', extractedUserType);
        }
        // Method 3: Check app_metadata (admin set)
        else if (user.app_metadata?.user_type) {
          extractedUserType = user.app_metadata.user_type;
          console.log('✅ Auth webhook user type from app_metadata:', extractedUserType);
        }
        // Method 4: Query database for user_type (fallback)
        else {
          console.log('⚠️ Auth webhook: No user_type in metadata, querying database...');
          try {
            const { data: dbUser, error } = await supabase
              .from('users')
              .select('user_type')
              .eq('id', user.id)
              .single();

            if (!error && dbUser?.user_type) {
              extractedUserType = dbUser.user_type;
              console.log('✅ Auth webhook user type from database query:', extractedUserType);
            }
          } catch (queryError) {
            console.log('⚠️ Auth webhook database query failed, using default:', queryError.message);
          }
        }

        console.log('🎯 Auth webhook final extracted user_type:', extractedUserType);

        const verificationEvent = {
          user_id: user.id,
          user_email: user.email,
          verified_at: user.email_confirmed_at,
          event_type: 'email_verified_auth_webhook',
          metadata: {
            user_type: extractedUserType,
            full_name: user.user_metadata?.full_name || user.raw_user_meta_data?.full_name || user.email.split('@')[0],
            verification_method: 'auth_webhook',
            metadata_sources_checked: {
              user_metadata: !!user.user_metadata?.user_type,
              raw_user_meta_data: !!user.raw_user_meta_data?.user_type,
              app_metadata: !!user.app_metadata?.user_type,
              database_query: extractedUserType !== 'customer' || (!user.user_metadata?.user_type && !user.raw_user_meta_data?.user_type && !user.app_metadata?.user_type)
            }
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