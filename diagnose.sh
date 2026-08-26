#!/bin/bash
# Run this ON YOUR VPS via SSH, from anywhere. Paste the FULL output back.
TOKEN="8698e65562bc16419f8f2b29a792d4fa9c97f20287b508b07c378e50a3e8207a"
URL="https://www.kanbooster.website"

echo "##################################################"
echo "# 1. Is there more than ONE admin.html on disk?"
echo "##################################################"
find / -xdev -iname "admin.html" -not -path "*/node_modules/*" 2>/dev/null -exec ls -la {} \;

echo ""
echo "##################################################"
echo "# 2. What does the LIVE site actually serve for loadCustomerRegister()?"
echo "##################################################"
curl -s "$URL/admin.html?nocache=$(date +%s)" | grep -n "async function loadCustomerRegister" -A 20

echo ""
echo "##################################################"
echo "# 3. What's on disk RIGHT NOW in your project folder (adjust path if wrong)?"
echo "##################################################"
find ~/botfiles -iname "admin.html" 2>/dev/null -exec ls -la {} \;
find ~/botfiles -iname "admin.html" 2>/dev/null -exec grep -n "async function loadCustomerRegister" -A 20 {} \;

echo ""
echo "##################################################"
echo "# 4. Which process is actually serving requests, and from where?"
echo "##################################################"
pm2 list 2>/dev/null
pm2 describe kanbooster 2>/dev/null | grep -i "script path\|cwd\|exec cwd" 2>/dev/null
echo "--- fallback if not pm2 ---"
ps aux | grep -i "node server" | grep -v grep

echo ""
echo "##################################################"
echo "# 5. nginx: what folder does it actually point to for this domain?"
echo "##################################################"
grep -rn "root\|proxy_pass\|server_name" /etc/nginx/sites-enabled/ 2>/dev/null | grep -i kanbooster -A2 -B2

echo ""
echo "##################################################"
echo "# 6. Raw API response right now, pretty printed, first 3 rows"
echo "##################################################"
curl -s "$URL/api/admin/customer-register" -H "x-admin-token: $TOKEN" | python3 -m json.tool 2>/dev/null | head -60

echo ""
echo "##################################################"
echo "# 7. File modification time - did your edit actually save?"
echo "##################################################"
find ~/botfiles -iname "admin.html" 2>/dev/null -exec stat -c '%n modified: %y' {} \;

echo ""
echo "##################################################"
echo "# 8. Is this a git repo? Any uncommitted/lost changes?"
echo "##################################################"
cd ~/botfiles/kanbooster 2>/dev/null && git status 2>/dev/null && git diff admin.html 2>/dev/null | head -50

echo ""
echo "##################################################"
echo "# 9. Node syntax check on the file that's actually deployed"
echo "##################################################"
find ~/botfiles -iname "admin.html" 2>/dev/null | while read f; do
  echo "Checking: $f"
  awk '/<script>/{flag=1; next} /<\/script>/{flag=0} flag' "$f" > /tmp/check_live.js
  node --check /tmp/check_live.js && echo "  -> SYNTAX OK" || echo "  -> SYNTAX ERROR (see above)"
done
