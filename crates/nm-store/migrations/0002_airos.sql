ALTER TABLE devices ADD COLUMN ssh_legacy_ok INTEGER NOT NULL DEFAULT 0 CHECK(ssh_legacy_ok IN (0,1));
