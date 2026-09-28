UPDATE settings
SET value_encrypted = value #>> '{}', value = '""'::jsonb, is_secret = TRUE
WHERE key = 'alert_webhook_url' AND value_encrypted IS NULL;
