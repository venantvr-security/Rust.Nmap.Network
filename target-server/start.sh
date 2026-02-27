#!/bin/bash

# Start SSH
service ssh start

# Start FTP
service vsftpd start

# Start a simple Python server on 8080 (simulates an API)
cd /var/www/html && python3 -m http.server 8080 &

# Start Nginx in foreground
nginx -g 'daemon off;'
