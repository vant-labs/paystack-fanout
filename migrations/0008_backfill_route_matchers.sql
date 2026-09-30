UPDATE routes
SET app_identifier = COALESCE(app_identifier, matcher->>'app_identifier'),
    environment = COALESCE(environment, matcher->>'environment'),
    metadata_app = CASE
        WHEN LEFT(metadata_app, LENGTH('__fanout_extended_matcher__:')) = '__fanout_extended_matcher__:'
            THEN matcher->>'metadata_app'
        ELSE metadata_app
    END
WHERE matcher IS NOT NULL;
