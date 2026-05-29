# KanBooster VPS Deployment Guide
# Google Cloud VPS + Nginx + PM2 + SSL

## FOLDER STRUCTURE ON YOUR VPS
```
/home/youruser/kanbooster/
├── server.js          ← Node.js server
├── package.json
├── .env               ← SECRET — never share this
├── public/
│   ├── index.html     ← Customer page
│   └── admin.html     ← Admin page
```

---

## STEP 1: Connect to your VPS
```bash
ssh youruser@your-vps-ip
```

---

## STEP 2: Install Node.js
```bash
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs
node --version   # should show v20.x
npm --version
```

---

## STEP 3: Install PM2 (keeps server running after reboot)
```bash
sudo npm install -g pm2
```

---

## STEP 4: Install Nginx
```bash
sudo apt update
sudo apt install nginx -y
sudo systemctl start nginx
sudo systemctl enable nginx
```

---

## STEP 5: Upload your files to VPS
# From your LOCAL machine, run:
```bash
# Create folder on VPS first
ssh youruser@your-vps-ip "mkdir -p /home/youruser/kanbooster/public"

# Upload all files
scp server.js youruser@your-vps-ip:/home/youruser/kanbooster/
scp package.json youruser@your-vps-ip:/home/youruser/kanbooster/
scp public/index.html youruser@your-vps-ip:/home/youruser/kanbooster/public/
scp public/admin.html youruser@your-vps-ip:/home/youruser/kanbooster/public/
```

---

## STEP 6: Create .env file on VPS
```bash
cd /home/youruser/kanbooster
nano .env
```

Paste this and fill in your real values:
```
SUPABASE_URL=https://yourproject.supabase.co
SUPABASE_SERVICE_KEY=your_SERVICE_ROLE_key_here
FLW_PUBLIC_KEY=FLWPUBK-xxxxxxxxxxxxxxxxxxxx-X
FLW_SECRET_KEY=FLWSECK-xxxxxxxxxxxxxxxxxxxx-X
FLW_SECRET_HASH=your_flw_webhook_secret
PORT=3000
SITE_URL=https://yourdomain.com
```

Save: Ctrl+X → Y → Enter

Secure the .env file:
```bash
chmod 600 .env
```

---

## STEP 7: Install dependencies and start server
```bash
cd /home/youruser/kanbooster
npm install
pm2 start server.js --name kanbooster
pm2 save
pm2 startup   # follow the command it gives you
```

Check server is running:
```bash
pm2 status
pm2 logs kanbooster
```

Test locally on VPS:
```bash
curl http://localhost:3000
```
Should return your HTML page.

---

## STEP 8: Configure Nginx as reverse proxy
```bash
sudo nano /etc/nginx/sites-available/kanbooster
```

Paste this (replace yourdomain.com with your real domain):
```nginx
server {
    listen 80;
    server_name yourdomain.com www.yourdomain.com;

    # Security headers
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Block common attack paths
    location ~ /\.(env|git|htaccess|htpasswd) {
        deny all;
        return 404;
    }

    location ~ \.(php|asp|aspx|jsp)$ {
        deny all;
        return 404;
    }

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
    limit_req_zone $binary_remote_addr zone=login:10m rate=1r/s;

    location /api/admin/login {
        limit_req zone=login burst=3 nodelay;
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location /api/ {
        limit_req zone=api burst=20 nodelay;
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_cache_bypass $http_upgrade;
    }
}
```

Save: Ctrl+X → Y → Enter

Enable the site:
```bash
sudo ln -s /etc/nginx/sites-available/kanbooster /etc/nginx/sites-enabled/
sudo nginx -t   # test config — should say "OK"
sudo systemctl reload nginx
```

---

## STEP 9: Point your Namecheap domain to VPS
In Namecheap → Domain List → Manage → Advanced DNS:

```
Type    Host    Value               TTL
A       @       YOUR_VPS_IP         Auto
A       www     YOUR_VPS_IP         Auto
```

Wait 5-15 minutes for DNS to propagate.

---

## STEP 10: Install SSL certificate (free HTTPS)
```bash
sudo apt install certbot python3-certbot-nginx -y
sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com
```

Follow the prompts. Certbot auto-renews every 90 days.

After SSL is installed, Nginx config auto-updates to redirect HTTP → HTTPS.

---

## STEP 11: Run Supabase SQL setup
1. Go to supabase.com → your project
2. Click SQL Editor
3. Open setup.sql from your files
4. IMPORTANT: Change the admin password in the INSERT line first
5. Click Run

---

## STEP 12: Test everything
```bash
# Check server running
pm2 status

# Check logs for errors
pm2 logs kanbooster --lines 50

# Test HTTPS
curl https://yourdomain.com
```

Visit:
- Customer page: https://yourdomain.com
- Admin panel: https://yourdomain.com/admin

---

## UPDATING YOUR FILES LATER
When you make changes to HTML or server.js:
```bash
# From local machine — upload changed files
scp server.js youruser@your-vps-ip:/home/youruser/kanbooster/
scp public/index.html youruser@your-vps-ip:/home/youruser/kanbooster/public/

# On VPS — restart server
pm2 restart kanbooster
```

---

## USEFUL PM2 COMMANDS
```bash
pm2 status              # check if running
pm2 logs kanbooster     # view live logs
pm2 restart kanbooster  # restart after code changes
pm2 stop kanbooster     # stop server
pm2 delete kanbooster   # remove from pm2
```

---

## SECURITY CHECKLIST
- [x] API keys in .env only — never in HTML
- [x] .env has chmod 600 (only you can read it)
- [x] Supabase service key only on server — never in browser
- [x] Rate limiting on all API endpoints
- [x] Extra strict rate limit on admin login (5 attempts per 15 mins)
- [x] Admin sessions expire after 8 hours
- [x] Helmet.js security headers
- [x] CORS locked to your domain only
- [x] Input sanitization on all endpoints
- [x] Device ID verification for voucher retrieval
- [x] Supabase RLS locks anon key from admin tables
- [x] Nginx blocks .env, .git, .php access attempts
- [x] HTTPS enforced via Let's Encrypt
- [x] Admin password stored in Supabase (not hardcoded)

---

## IF SERVER CRASHES ON REBOOT
```bash
pm2 startup   # generates a command — copy and run it
pm2 save      # saves current process list
```

---

## CHANGE ADMIN PASSWORD
Go to Supabase → Table Editor → admin_users → edit the row
Or run SQL:
```sql
UPDATE admin_users SET password = 'your_new_password' WHERE username = 'admin';
```

---

## ADD SECOND ADMIN
```sql
INSERT INTO admin_users (username, password, active)
VALUES ('manager', 'manager_password_here', true);
```
