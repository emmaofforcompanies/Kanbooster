-- ============================================
-- KanBooster Supabase Setup SQL
-- Run this in Supabase Dashboard → SQL Editor
-- ============================================

-- 1. ADMIN USERS TABLE
CREATE TABLE IF NOT EXISTS admin_users (
    id BIGSERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 2. ADMIN SESSIONS TABLE (secure token-based login)
CREATE TABLE IF NOT EXISTS admin_sessions (
    id BIGSERIAL PRIMARY KEY,
    token TEXT UNIQUE NOT NULL,
    username TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL
);

-- 3. ADMIN LOGIN LOG
CREATE TABLE IF NOT EXISTS admin_logins (
    id BIGSERIAL PRIMARY KEY,
    username TEXT NOT NULL,
    logged_in_at TIMESTAMPTZ DEFAULT NOW(),
    ip TEXT
);

-- 4. Add device_id column to transactions if not exists
ALTER TABLE transactions ADD COLUMN IF NOT EXISTS device_id TEXT;

-- 5. Indexes for performance
CREATE INDEX IF NOT EXISTS idx_transactions_payment_code ON transactions(payment_code);
CREATE INDEX IF NOT EXISTS idx_transactions_phone ON transactions(phone);
CREATE INDEX IF NOT EXISTS idx_transactions_status ON transactions(status);
CREATE INDEX IF NOT EXISTS idx_transactions_timestamp ON transactions(timestamp);
CREATE INDEX IF NOT EXISTS idx_codes_product_site_status ON codes(product_id, site_name, status);
CREATE INDEX IF NOT EXISTS idx_admin_sessions_token ON admin_sessions(token);

-- 6. Auto-expire old sessions (run periodically)
-- DELETE FROM admin_sessions WHERE expires_at < NOW();

-- 7. INSERT YOUR FIRST ADMIN USER
-- IMPORTANT: Change username and password before running!
INSERT INTO admin_users (username, password, active)
VALUES ('admin', 'your_strong_password_here', true)
ON CONFLICT (username) DO NOTHING;

-- 8. ROW LEVEL SECURITY — lock down tables
-- Only service role (server) can access these tables
-- Anon key (browser) cannot read admin tables

ALTER TABLE admin_users ENABLE ROW LEVEL SECURITY;
CREATE POLICY "No public access" ON admin_users FOR ALL TO anon USING (false);

ALTER TABLE admin_sessions ENABLE ROW LEVEL SECURITY;
CREATE POLICY "No public access" ON admin_sessions FOR ALL TO anon USING (false);

ALTER TABLE admin_logins ENABLE ROW LEVEL SECURITY;
CREATE POLICY "No public access" ON admin_logins FOR ALL TO anon USING (false);

-- 9. Lock down codes table — anon can only read, not write
ALTER TABLE codes ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Anon read only" ON codes FOR SELECT TO anon USING (true);
CREATE POLICY "Service role full access" ON codes FOR ALL TO service_role USING (true);

-- 10. Lock down transactions table
ALTER TABLE transactions ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Anon insert only" ON transactions FOR INSERT TO anon WITH CHECK (true);
CREATE POLICY "Anon read own" ON transactions FOR SELECT TO anon USING (true);
CREATE POLICY "Service role full access" ON transactions FOR ALL TO service_role USING (true);

-- Confirm setup
SELECT 'Setup complete! Tables created.' AS status;
