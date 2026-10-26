-- Optional manual migration for an existing LMS database.
-- The updated app.py also adds this column automatically when it detects an older schema.
USE learning_management_db;
ALTER TABLE candidates
  ADD COLUMN status ENUM('pending','approved','rejected') NOT NULL DEFAULT 'pending' AFTER password_hash;

-- After migration, approve existing candidates from Admin > Manage Candidates.
-- If you want to approve all previously registered accounts, run this intentionally:
-- UPDATE candidates SET status = 'approved' WHERE status = 'pending';
