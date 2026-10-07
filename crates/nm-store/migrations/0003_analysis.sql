ALTER TABLE credential_profiles ADD COLUMN is_vendor_default INTEGER NOT NULL DEFAULT 0;
ALTER TABLE sites ADD COLUMN max_distance_m INTEGER;
ALTER TABLE devices ADD COLUMN interface_roles_json TEXT NOT NULL DEFAULT "{}";
