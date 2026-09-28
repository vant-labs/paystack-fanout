UPDATE routes SET target_url = destination_url WHERE target_url IS NULL;
ALTER TABLE routes ALTER COLUMN target_url SET NOT NULL;
