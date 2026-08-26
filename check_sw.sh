#!/bin/bash
echo "### Any service worker files anywhere in the project? ###"
find ~/botfiles/kanbooster -iname "*service-worker*" -o -iname "sw.js" -o -iname "manifest.json" 2>/dev/null

echo ""
echo "### Contents of public/ folder ###"
ls -la ~/botfiles/kanbooster/public/ 2>/dev/null

echo ""
echo "### Does index.html (customer app) register a service worker? ###"
grep -n "serviceWorker\|register(" ~/botfiles/kanbooster/public/index.html 2>/dev/null
grep -rn "serviceWorker\|register(" ~/botfiles/kanbooster/public/*.js 2>/dev/null

echo ""
echo "### Does server.js serve admin.html and index.html from the same static root? ###"
grep -n "express.static\|app.get('/admin\|app.get('/'\|sendFile" ~/botfiles/kanbooster/server.js
