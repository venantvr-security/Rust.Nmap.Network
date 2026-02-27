# =============================================================================
# TARGET SERVER - Serveur cible multi-services pour tests IDS
# =============================================================================
#
# OBJECTIF:
# Fournir une cible réaliste pour tester les détections IDS.
# Ce serveur expose plusieurs services vulnérables intentionnellement
# pour permettre l'apprentissage des techniques d'attaque et de défense.
#
# SERVICES EXPOSÉS:
# ┌──────────┬───────────────────────────────────────────────────────┐
# │ Port 21  │ FTP (vsftpd) - Accès anonyme activé                   │
# │          │ → Fichiers sensibles dans /var/ftp/pub                │
# ├──────────┼───────────────────────────────────────────────────────┤
# │ Port 22  │ SSH (OpenSSH) - Root login autorisé                   │
# │          │ → Password: ids_lab_2024                              │
# ├──────────┼───────────────────────────────────────────────────────┤
# │ Port 80  │ HTTP (Nginx) - Site web statique                      │
# │          │ → Pages: /, /robots.txt, /api.json                    │
# ├──────────┼───────────────────────────────────────────────────────┤
# │ Port 8080│ API (Netcat listener)                                 │
# │          │ → Simule un endpoint API vulnérable                   │
# └──────────┴───────────────────────────────────────────────────────┘
#
# AVERTISSEMENT SÉCURITÉ:
# Ce serveur est INTENTIONNELLEMENT VULNÉRABLE.
# Ne JAMAIS exposer sur un réseau de production!
# Utiliser uniquement dans des réseaux Docker isolés.
#
# =============================================================================

FROM debian:bookworm-slim

# -----------------------------------------------------------------------------
# INSTALLATION DES SERVICES
# -----------------------------------------------------------------------------
# Packages installés:
# - nginx: Serveur web HTTP
# - openssh-server: Serveur SSH
# - vsftpd: Serveur FTP
# - netcat-openbsd: Pour simuler des services TCP
# - python3: Pour scripts d'automatisation
# - curl: Pour les tests de connectivité
RUN apt-get update && apt-get install -y --no-install-recommends \
    nginx \
    openssh-server \
    vsftpd \
    netcat-openbsd \
    python3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# -----------------------------------------------------------------------------
# CONFIGURATION SSH (VULNÉRABLE - INTENTIONNEL)
# -----------------------------------------------------------------------------
# Configuration volontairement permissive pour les tests:
# - Root login autorisé (dangereux en production!)
# - Authentification par mot de passe (pas de clés)
# - Mot de passe: ids_lab_2024
RUN mkdir /var/run/sshd && \
    echo 'root:ids_lab_2024' | chpasswd && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

# -----------------------------------------------------------------------------
# CONFIGURATION FTP (ACCÈS ANONYME)
# -----------------------------------------------------------------------------
# Crée des fichiers "sensibles" pour démontrer le risque
# d'un FTP mal configuré (accès anonyme)
RUN mkdir -p /var/ftp/pub && \
    echo "IDS Lab - FTP Server" > /var/ftp/pub/readme.txt && \
    echo "Confidential files here..." > /var/ftp/pub/secret.txt
COPY vsftpd.conf /etc/vsftpd.conf

# -----------------------------------------------------------------------------
# CONFIGURATION NGINX (SERVEUR WEB)
# -----------------------------------------------------------------------------
# Pages web statiques simulant un site d'entreprise
# Contient des informations utiles pour les scans (robots.txt, api.json)
COPY html/ /var/www/html/
COPY nginx.conf /etc/nginx/sites-available/default

# -----------------------------------------------------------------------------
# SCRIPT DE DÉMARRAGE
# -----------------------------------------------------------------------------
# Lance tous les services simultanément
COPY start.sh /start.sh
RUN chmod +x /start.sh

# Ports exposés (documentation)
EXPOSE 21 22 80 8080

# Point d'entrée: lance tous les services
CMD ["/start.sh"]
