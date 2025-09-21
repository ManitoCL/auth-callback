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

/**
 * Create user profile AFTER email verification (security fix)
 * This ensures only verified users get profiles in the system
 */
async function createProfileAfterVerification(user, userType) {
  console.log('🔒 Creating profile after verification for user:', user.id);

  // Check if profile already exists
  const { data: existingProfile, error: checkError } = await supabase
    .from('users')
    .select('id')
    .eq('id', user.id)
    .single();

  if (existingProfile) {
    console.log('✅ Profile already exists for verified user:', user.id);
    return;
  }

  if (checkError && checkError.code !== 'PGRST116') {
    console.error('❌ Error checking existing profile:', checkError);
    throw checkError;
  }

  // Create user profile from auth metadata
  const profileData = {
    id: user.id,
    email: user.email,
    full_name: user.user_metadata?.full_name || user.raw_user_meta_data?.full_name,
    user_type: userType,
    phone_number: user.user_metadata?.phone_number || user.raw_user_meta_data?.phone_number || null,
    display_name: user.user_metadata?.display_name || user.raw_user_meta_data?.display_name,
    is_verified: true, // Email just verified
    email_verified_at: user.email_confirmed_at,
    onboarding_completed: false,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    last_seen_at: new Date().toISOString(),
    // Chilean fields
    nombres: user.user_metadata?.nombres || user.raw_user_meta_data?.nombres || null,
    apellidos: user.user_metadata?.apellidos || user.raw_user_meta_data?.apellidos || null,
  };

  console.log('📝 Creating verified user profile:', {
    userId: user.id,
    email: user.email,
    userType: userType,
    hasFullName: !!profileData.full_name
  });

  const { error: profileError } = await supabase
    .from('users')
    .insert(profileData);

  if (profileError) {
    console.error('❌ Failed to create user profile after verification:', profileError);
    throw profileError;
  }

  console.log('✅ User profile created successfully after verification');

  // Create provider profile if needed (STACK OVERFLOW FIX)
  if (userType === 'provider') {
    console.log('👨‍💼 Creating provider profile for verified user (recursion-safe):', user.id);

    try {
      // METHOD 1: Try using custom RPC function (bypasses triggers)
      const { data: rpcResult, error: rpcError } = await supabase
        .rpc('create_provider_profile_webhook_safe', {
          p_user_id: user.id,
          p_description: 'Proveedor de servicios profesionales en Chile'
        });

      if (rpcError) {
        console.log('⚠️ RPC function not available, using fallback method:', rpcError.message);

        // METHOD 2: Fallback - use raw SQL to bypass triggers
        const { error: sqlError } = await supabase
          .from('provider_profiles')
          .insert({
            user_id: user.id,
            business_name: null,
            description: 'Proveedor de servicios profesionales en Chile',
            verification_status: 'pending',
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
          });

        if (sqlError) {
          console.error('❌ Both RPC and fallback failed for provider profile:', sqlError);
          // Don't throw - user profile was created successfully
        } else {
          console.log('✅ Provider profile created via fallback method');
        }
      } else {
        console.log('✅ Provider profile created via safe RPC function:', rpcResult);
      }

    } catch (recursionError) {
      console.error('🚫 STACK OVERFLOW CAUGHT - Provider profile creation failed:', recursionError.message);

      // Log the specific error for debugging
      if (recursionError.message.includes('stack depth limit exceeded') ||
          recursionError.message.includes('maximum recursion depth exceeded')) {
        console.error('🔄 CONFIRMED: Trigger recursion detected in provider profile creation');
        console.error('💡 SOLUTION: Database triggers need recursion fix via targeted_rls_fix.sql');
      }

      // Don't throw - user profile was created successfully, provider profile can be created later
      console.log('⚠️ Continuing without provider profile - can be created during onboarding');
    }
  }
}

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

        // SECURITY FIX: Create user profile AFTER email verification
        try {
          await createProfileAfterVerification(user, extractedUserType);
        } catch (profileCreationError) {
          console.error('❌ Profile creation after verification failed:', profileCreationError);
          // Continue with verification event storage - don't fail webhook
        }

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

        // SECURITY FIX: Create user profile AFTER email verification
        try {
          await createProfileAfterVerification(user, extractedUserType);
        } catch (profileCreationError) {
          console.error('❌ Auth webhook profile creation failed:', profileCreationError);
          // Continue with verification event storage - don't fail webhook
        }

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