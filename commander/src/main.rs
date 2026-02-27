// =============================================================================
// IDS LAB COMMANDER - Application principale
// =============================================================================
//
// DESCRIPTION:
// Dashboard web pour piloter les laboratoires IDS (Snort, Suricata, Zeek).
// Fournit une interface unifiée pour:
// - Démarrer/arrêter les containers Docker
// - Changer les niveaux de sécurité (5 niveaux de règles)
// - Visualiser l'état du système
// - Cookbook d'attaques pour tests d'évasion
//
// STACK TECHNIQUE:
// - Axum: Framework web async moderne
// - Bollard: Client Docker natif Rust
// - HTMX: Interactions frontend sans JS complexe
// - Mermaid: Diagrammes d'architecture
//
// ARCHITECTURE HTMX:
// Le frontend utilise HTMX pour les interactions:
// 1. L'utilisateur clique sur un bouton (hx-post="/start/xxx")
// 2. HTMX envoie une requête POST au serveur
// 3. Le serveur exécute l'action et renvoie le HTML complet
// 4. HTMX remplace le contenu de la page (hx-target="body")
//
// Cela permet d'avoir une application interactive sans écrire de JavaScript.
//
// =============================================================================

use axum::{
    extract::Path,
    response::Html,
    routing::{get, post},
    Router,
};
use bollard::container::{LogsOptions, StartContainerOptions, StopContainerOptions};
use bollard::Docker;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use futures_util::StreamExt;
use tower_http::services::ServeDir;

/// Retourne le chemin racine du projet.
/// Peut être surchargé via la variable d'environnement PROJECT_ROOT.
fn get_project_root() -> PathBuf {
    std::env::var("PROJECT_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/home/rvv/Bureau/Rust.Nmap.Network"))
}

/// Point d'entrée principal de l'application.
/// Configure les routes et démarre le serveur HTTP sur le port 3000.
#[tokio::main]
async fn main() {
    let static_dir = get_project_root().join("commander/static");

    // Configuration des routes Axum
    // Chaque route correspond à une action ou une page
    let app = Router::new()
        // Pages HTML
        .route("/", get(dashboard))                      // Dashboard principal
        .route("/setup", get(setup_page))                // Guide d'installation

        // Actions sur les containers (appelées via HTMX)
        .route("/start/{id}", post(start_container))     // Démarrer un container
        .route("/stop/{id}", post(stop_container))       // Arrêter un container
        .route("/restart/{id}", post(restart_container)) // Redémarrer un container

        // Gestion des templates de règles
        .route("/apply/{ids}/{level}", post(apply_template)) // Appliquer niveau 1-5

        // Logs et diagnostics
        .route("/logs/{id}", get(get_logs))              // Voir les logs d'un container
        .route("/reset-logs/{ids}", post(reset_logs))    // Réinitialiser les logs
        .route("/system-info", get(system_info))         // Infos système

        // Gestion des labs complets (docker compose up/down)
        .route("/lab/start/{lab}", post(start_lab))      // Démarrer snort/suricata/zeek
        .route("/lab/stop/{lab}", post(stop_lab))        // Arrêter un lab

        // Fichiers statiques (CSS, JS)
        .nest_service("/static", ServeDir::new(static_dir));

    // Démarrage du serveur HTTP
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║           IDS Lab Commander - Academic Edition               ║");
    println!("╠══════════════════════════════════════════════════════════════╣");
    println!("║  Dashboard:    http://localhost:3000                         ║");
    println!("║  Setup Guide:  http://localhost:3000/setup                   ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");
    axum::serve(listener, app).await.unwrap();
}

// ============================================================================
// FONCTIONS D'INFORMATION SYSTÈME
// ============================================================================
// Ces fonctions collectent des informations sur l'environnement Docker
// pour les afficher dans le dashboard.

/// Récupère la liste des réseaux Docker (bridges).
/// Retourne: Vec<(nom, id, driver)>
/// Utilisé pour afficher les réseaux dans le dashboard.
fn get_docker_bridges() -> Vec<(String, String, String)> {
    let output = Command::new("docker")
        .args(["network", "ls", "--format", "{{.Name}}\t{{.ID}}\t{{.Driver}}"])
        .output();

    match output {
        Ok(o) => {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .filter(|l| l.contains("bridge") || l.contains("snort") || l.contains("suricata") || l.contains("zeek"))
                .map(|l| {
                    let parts: Vec<&str> = l.split('\t').collect();
                    (
                        parts.get(0).unwrap_or(&"").to_string(),
                        parts.get(1).unwrap_or(&"").to_string(),
                        parts.get(2).unwrap_or(&"").to_string(),
                    )
                })
                .collect()
        }
        Err(_) => vec![],
    }
}

/// Récupère les interfaces réseau bridge avec leurs IPs.
/// Utilise la commande `ip addr show` pour lister les interfaces.
/// Retourne: Vec<(interface, ip/cidr)>
fn get_bridge_interfaces() -> Vec<(String, String)> {
    let output = Command::new("ip")
        .args(["addr", "show"])
        .output();

    match output {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            let mut interfaces = vec![];
            let mut current_iface = String::new();

            for line in stdout.lines() {
                if line.contains("br-") || line.contains("docker0") {
                    if let Some(name) = line.split(':').nth(1) {
                        current_iface = name.trim().split('@').next().unwrap_or("").to_string();
                    }
                }
                if !current_iface.is_empty() && line.contains("inet ") {
                    if let Some(ip) = line.split_whitespace().nth(1) {
                        interfaces.push((current_iface.clone(), ip.to_string()));
                        current_iface.clear();
                    }
                }
            }
            interfaces
        }
        Err(_) => vec![],
    }
}

/// Récupère les détails de tous les containers liés aux labs IDS.
/// Filtre sur les noms contenant: snort, suricata, zeek, target, evebox, editor
/// Retourne: Vec<HashMap> avec clés: name, status, image, id, ip
fn get_container_details() -> Vec<HashMap<String, String>> {
    let output = Command::new("docker")
        .args(["ps", "-a", "--format", "{{.Names}}\t{{.Status}}\t{{.Image}}\t{{.ID}}"])
        .output();

    match output {
        Ok(o) => {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .filter(|l| {
                    l.contains("snort") || l.contains("suricata") || l.contains("zeek")
                    || l.contains("target") || l.contains("evebox") || l.contains("editor") || l.contains("reloader")
                })
                .map(|l| {
                    let parts: Vec<&str> = l.split('\t').collect();
                    let mut map = HashMap::new();
                    map.insert("name".into(), parts.get(0).unwrap_or(&"").to_string());
                    map.insert("status".into(), parts.get(1).unwrap_or(&"").to_string());
                    map.insert("image".into(), parts.get(2).unwrap_or(&"").to_string());
                    map.insert("id".into(), parts.get(3).unwrap_or(&"").to_string());

                    // Get IP
                    let ip_output = Command::new("docker")
                        .args(["inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", parts.get(0).unwrap_or(&"")])
                        .output();
                    if let Ok(ip_out) = ip_output {
                        let ip = String::from_utf8_lossy(&ip_out.stdout).trim().to_string();
                        map.insert("ip".into(), if ip.is_empty() { "-".into() } else { ip });
                    }
                    map
                })
                .collect()
        }
        Err(_) => vec![],
    }
}

/// Vérifie si Docker est accessible sans sudo.
/// Retourne: (ok: bool, message: String)
/// Si ok=false, le message contient l'erreur.
fn check_docker_permissions() -> (bool, String) {
    let output = Command::new("docker").args(["ps"]).output();
    match output {
        Ok(o) => {
            if o.status.success() {
                (true, "Docker accessible sans sudo".into())
            } else {
                (false, String::from_utf8_lossy(&o.stderr).to_string())
            }
        }
        Err(e) => (false, e.to_string()),
    }
}

/// Détecte le niveau de sécurité actuel d'un IDS.
/// Lit la première ligne du fichier de règles pour identifier le niveau.
/// Les templates contiennent un commentaire "Level X" ou le nom du niveau.
///
/// Arguments:
/// - ids: "snort", "suricata", ou "zeek"
///
/// Retourne: "1 - Minimal", "2 - Basic", ..., "5 - Paranoid", ou "Custom"
fn get_current_rule_level(ids: &str) -> String {
    let root = get_project_root();
    let rules_path = match ids {
        "snort" => root.join("snort-lab/config/local.rules"),
        "suricata" => root.join("suricata-lab/rules/local.rules"),
        "zeek" => root.join("zeek-lab/scripts/local.zeek"),
        _ => return "?".into(),
    };

    if let Ok(content) = fs::read_to_string(&rules_path) {
        let first_line = content.lines().next().unwrap_or("");
        if first_line.contains("Level 1") || first_line.contains("Minimal") {
            "1 - Minimal".into()
        } else if first_line.contains("Level 2") || first_line.contains("Basic") {
            "2 - Basic".into()
        } else if first_line.contains("Level 3") || first_line.contains("Moderate") {
            "3 - Moderate".into()
        } else if first_line.contains("Level 4") || first_line.contains("Strict") {
            "4 - Strict".into()
        } else if first_line.contains("Level 5") || first_line.contains("Paranoid") {
            "5 - Paranoid".into()
        } else {
            "Custom".into()
        }
    } else {
        "N/A".into()
    }
}

// ============================================================================
// DASHBOARD PRINCIPAL
// ============================================================================
// Génère la page HTML du dashboard avec:
// - Diagramme d'architecture (Mermaid)
// - État des containers (IDS, targets, services)
// - Sélecteur de niveaux de sécurité
// - Cookbook d'attaques (Nmap, Scapy, Hping3)
// - Informations système

/// Génère le dashboard HTML complet.
/// Cette fonction collecte toutes les informations système et génère
/// une page HTML avec HTMX pour les interactions.
async fn dashboard() -> Html<String> {
    let containers = get_container_details();
    let bridges = get_docker_bridges();
    let interfaces = get_bridge_interfaces();
    let (docker_ok, _docker_msg) = check_docker_permissions();

    // Build container tables
    let mut ids_rows = String::new();
    let mut target_rows = String::new();
    let mut service_rows = String::new();

    for c in &containers {
        let name = c.get("name").map(|s| s.as_str()).unwrap_or("");
        let ip = c.get("ip").map(|s| s.as_str()).unwrap_or("-");
        let status = c.get("status").map(|s| s.as_str()).unwrap_or("");
        let id = c.get("id").map(|s| s.as_str()).unwrap_or("");
        let short_id = &id[..12.min(id.len())];

        let is_running = status.contains("Up");
        let status_class = if is_running { "running" } else { "stopped" };
        let status_icon = if is_running { "●" } else { "○" };

        let action_btns = format!(
            r#"<button class="btn {}" hx-post="/{}/{}" hx-target="body">{}</button>
               <button class="btn neutral" hx-post="/restart/{}" hx-target="body">↻</button>"#,
            if is_running { "stop" } else { "start" },
            if is_running { "stop" } else { "start" },
            short_id,
            if is_running { "Stop" } else { "Start" },
            short_id
        );

        let row = format!(
            r#"<tr class="{}"><td>{}</td><td><code>{}</code></td><td>{} {}</td><td>{}</td></tr>"#,
            status_class, name, ip, status_icon,
            if is_running { "Running" } else { "Stopped" },
            action_btns
        );

        if name.contains("_ids") || name == "snort" || name == "suricata" || name == "zeek" {
            ids_rows.push_str(&row);
        } else if name.contains("target") {
            target_rows.push_str(&row);
        } else {
            service_rows.push_str(&row);
        }
    }

    // Network info
    let mut network_html = String::new();
    for (name, id, driver) in &bridges {
        network_html.push_str(&format!(
            r#"<tr><td>{}</td><td><code>{}</code></td><td>{}</td></tr>"#,
            name, &id[..12.min(id.len())], driver
        ));
    }

    let mut interfaces_html = String::new();
    for (iface, ip) in &interfaces {
        interfaces_html.push_str(&format!(
            r#"<tr><td><code>{}</code></td><td><code>{}</code></td></tr>"#,
            iface, ip
        ));
    }

    // Current levels
    let snort_level = get_current_rule_level("snort");
    let suricata_level = get_current_rule_level("suricata");
    let zeek_level = get_current_rule_level("zeek");

    // Find target IPs for attack cookbook
    let suricata_target = containers.iter()
        .find(|c| c.get("name").map(|n| n.contains("target_suricata")).unwrap_or(false))
        .and_then(|c| c.get("ip"))
        .map(|s| s.as_str())
        .unwrap_or("172.29.0.100");

    let html = format!(r##"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>IDS Lab Commander - Academic Edition</title>
    <link rel="stylesheet" href="/static/css/dashboard.css">
    <script src="https://unpkg.com/htmx.org@1.9.10"></script>
    <script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
</head>
<body>
    <div class="header">
        <h1>🛡️ IDS Lab Commander</h1>
        <p class="header-subtitle">Laboratoire académique d'évasion IDS - Test Snort, Suricata, Zeek</p>
        <nav class="nav">
            <a href="/" class="active">Dashboard</a>
            <a href="/setup">Setup Guide</a>
            <a href="http://localhost:5636" target="_blank">EveBox ↗</a>
        </nav>
    </div>

    <div class="main">
        <div class="main-content">
            <!-- Architecture Diagram -->
            <div class="card">
                <div class="card-header">
                    <h2>🏗️ Architecture Réseau</h2>
                </div>
                <div class="card-body">
                    <div class="mermaid">
graph TB
    subgraph LOCALHOST["🖥️ LOCALHOST - Attaquant"]
        NMAP["nmap / scapy / hping3"]
    end

    subgraph SNORT_NET["snort_net 172.28.0.0/24"]
        SNORT_IDS["🛡️ snort_ids<br/>172.28.0.10"]
        TARGET_SNORT["🎯 target_snort<br/>172.28.0.100"]
    end

    subgraph SURICATA_NET["suricata_net 172.29.0.0/24"]
        SURICATA_IDS["🛡️ suricata_ids<br/>172.29.0.10"]
        TARGET_SURICATA["🎯 target_suricata<br/>172.29.0.100"]
    end

    subgraph ZEEK_NET["zeek_net 172.30.0.0/24"]
        ZEEK_IDS["🛡️ zeek_ids<br/>172.30.0.10"]
        TARGET_ZEEK["🎯 target_zeek<br/>172.30.0.100"]
    end

    NMAP -->|br-snort| SNORT_NET
    NMAP -->|br-suricata| SURICATA_NET
    NMAP -->|br-zeek| ZEEK_NET

    SNORT_IDS -.->|monitor| TARGET_SNORT
    SURICATA_IDS -.->|monitor| TARGET_SURICATA
    ZEEK_IDS -.->|monitor| TARGET_ZEEK
                    </div>
                </div>
            </div>

            <!-- Lab Selector -->
            <div class="card" style="background: linear-gradient(135deg, #1e3a5f 0%, #1a1a2e 100%);">
                <div class="card-header">
                    <h2>🚀 Sélection du Lab</h2>
                </div>
                <div class="card-body">
                    <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 1rem;">
                        <div class="lab-card">
                            <h3 style="margin-bottom: 0.5rem;">🐷 SNORT Lab</h3>
                            <p style="font-size: 0.8rem; color: var(--text-secondary);">Cible: <code>172.28.0.100</code></p>
                            <p style="font-size: 0.75rem; color: var(--text-secondary);">Ports: 21, 22, 80, 8080</p>
                            <div style="margin-top: 0.75rem; display: flex; gap: 0.5rem;">
                                <button class="btn start" hx-post="/lab/start/snort" hx-target="body">▶ Start</button>
                                <button class="btn stop" hx-post="/lab/stop/snort" hx-target="body">■ Stop</button>
                            </div>
                        </div>
                        <div class="lab-card">
                            <h3 style="margin-bottom: 0.5rem;">🦊 SURICATA Lab</h3>
                            <p style="font-size: 0.8rem; color: var(--text-secondary);">Cible: <code>172.29.0.100</code></p>
                            <p style="font-size: 0.75rem; color: var(--text-secondary);">Ports: 21, 22, 80, 8080</p>
                            <div style="margin-top: 0.75rem; display: flex; gap: 0.5rem;">
                                <button class="btn start" hx-post="/lab/start/suricata" hx-target="body">▶ Start</button>
                                <button class="btn stop" hx-post="/lab/stop/suricata" hx-target="body">■ Stop</button>
                            </div>
                        </div>
                        <div class="lab-card">
                            <h3 style="margin-bottom: 0.5rem;">👁️ ZEEK Lab</h3>
                            <p style="font-size: 0.8rem; color: var(--text-secondary);">Cible: <code>172.30.0.100</code></p>
                            <p style="font-size: 0.75rem; color: var(--text-secondary);">Ports: 21, 22, 80, 8080</p>
                            <div style="margin-top: 0.75rem; display: flex; gap: 0.5rem;">
                                <button class="btn start" hx-post="/lab/start/zeek" hx-target="body">▶ Start</button>
                                <button class="btn stop" hx-post="/lab/stop/zeek" hx-target="body">■ Stop</button>
                            </div>
                        </div>
                    </div>
                    <div class="info-callout" style="margin-top: 1rem;">
                        <strong>Services sur chaque cible:</strong> HTTP (80), SSH (22), FTP (21), API (8080)<br>
                        <strong>Page web:</strong> <code>http://&lt;target_ip&gt;/</code> | <strong>FTP:</strong> anonymous login
                    </div>
                </div>
            </div>

            <!-- IDS Containers -->
            <div class="card">
                <div class="card-header">
                    <h2>🔒 IDS Engines</h2>
                    <span class="status-badge {0}">{1}</span>
                </div>
                <div class="card-body">
                    <table>
                        <tr><th>Container</th><th>IP</th><th>Status</th><th>Actions</th></tr>
                        {2}
                    </table>
                </div>
            </div>

            <!-- Targets -->
            <div class="card">
                <div class="card-header">
                    <h2>🎯 Targets (Serveur Multi-Services)</h2>
                </div>
                <div class="card-body">
                    <p style="font-size: 0.85rem; color: var(--text-secondary); margin-bottom: 0.75rem;">
                        Chaque cible expose: <strong>HTTP</strong> (80), <strong>SSH</strong> (22), <strong>FTP</strong> (21), <strong>API</strong> (8080)
                    </p>
                    <table>
                        <tr><th>Container</th><th>IP</th><th>Status</th><th>Actions</th></tr>
                        {3}
                    </table>
                </div>
            </div>

            <!-- Security Level Templates -->
            <div class="card">
                <div class="card-header">
                    <h2>📊 Niveaux de Sécurité</h2>
                </div>
                <div class="card-body">
                    <p style="color: var(--text-secondary); margin-bottom: 1rem; font-size: 0.85rem;">
                        Sélectionnez un niveau pour chaque IDS. Les règles sont rechargées automatiquement.
                    </p>
                    <div class="templates-grid">
                        <div class="template-card">
                            <h3>🐷 SNORT</h3>
                            <div class="current">Actuel: {4}</div>
                            <button class="level-btn level-1" hx-post="/apply/snort/1" hx-target="body">1 - Minimal <span class="desc">Très perméable</span></button>
                            <button class="level-btn level-2" hx-post="/apply/snort/2" hx-target="body">2 - Basic <span class="desc">Scans évidents</span></button>
                            <button class="level-btn level-3" hx-post="/apply/snort/3" hx-target="body">3 - Moderate <span class="desc">Équilibré</span></button>
                            <button class="level-btn level-4" hx-post="/apply/snort/4" hx-target="body">4 - Strict <span class="desc">Sensible</span></button>
                            <button class="level-btn level-5" hx-post="/apply/snort/5" hx-target="body">5 - Paranoid <span class="desc">Maximum</span></button>
                        </div>
                        <div class="template-card">
                            <h3>🦊 SURICATA</h3>
                            <div class="current">Actuel: {5}</div>
                            <button class="level-btn level-1" hx-post="/apply/suricata/1" hx-target="body">1 - Minimal <span class="desc">Très perméable</span></button>
                            <button class="level-btn level-2" hx-post="/apply/suricata/2" hx-target="body">2 - Basic <span class="desc">Scans évidents</span></button>
                            <button class="level-btn level-3" hx-post="/apply/suricata/3" hx-target="body">3 - Moderate <span class="desc">Équilibré</span></button>
                            <button class="level-btn level-4" hx-post="/apply/suricata/4" hx-target="body">4 - Strict <span class="desc">Sensible</span></button>
                            <button class="level-btn level-5" hx-post="/apply/suricata/5" hx-target="body">5 - Paranoid <span class="desc">Maximum</span></button>
                        </div>
                        <div class="template-card">
                            <h3>👁️ ZEEK</h3>
                            <div class="current">Actuel: {6}</div>
                            <button class="level-btn level-1" hx-post="/apply/zeek/1" hx-target="body">1 - Minimal <span class="desc">Très perméable</span></button>
                            <button class="level-btn level-2" hx-post="/apply/zeek/2" hx-target="body">2 - Basic <span class="desc">Scans évidents</span></button>
                            <button class="level-btn level-3" hx-post="/apply/zeek/3" hx-target="body">3 - Moderate <span class="desc">Équilibré</span></button>
                            <button class="level-btn level-4" hx-post="/apply/zeek/4" hx-target="body">4 - Strict <span class="desc">Sensible</span></button>
                            <button class="level-btn level-5" hx-post="/apply/zeek/5" hx-target="body">5 - Paranoid <span class="desc">Maximum</span></button>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Attack Cookbook -->
            <div class="card">
                <div class="card-header">
                    <h2>📖 Cookbook d'Attaques</h2>
                </div>
                <div class="card-body">
                    <div class="tabs">
                        <button class="tab active" onclick="showTab('nmap')">Nmap</button>
                        <button class="tab" onclick="showTab('scapy')">Scapy</button>
                        <button class="tab" onclick="showTab('hping')">Hping3</button>
                    </div>

                    <div id="nmap" class="tab-content active" style="padding-top: 1rem;">
                        <div class="attack-cookbook">
                            <h4>🔍 Scans de base</h4>
                            <pre><code># SYN Scan (détecté niveau ≥2)
sudo nmap -sS {7}

# Full TCP Connect (détecté niveau ≥2)
nmap -sT {7}</code><button class="copy-btn" onclick="copyCode(this)">Copy</button></pre>

                            <h4>🥷 Techniques d'évasion</h4>
                            <pre><code># Fragmentation IP (évite niveau ≤3)
sudo nmap -f {7}

# Fragmentation max (évite niveau ≤4)
sudo nmap -f -f --mtu 8 {7}

# Timing lent T0 (évite détection par seuil)
sudo nmap -T0 {7}

# Decoys (brouille la source)
sudo nmap -D RND:10 {7}

# Idle/Zombie scan (pas de paquets directs)
sudo nmap -sI zombie_host {7}

# Source port 53 (DNS - souvent autorisé)
sudo nmap --source-port 53 {7}</code><button class="copy-btn" onclick="copyCode(this)">Copy</button></pre>
                        </div>
                    </div>

                    <div id="scapy" class="tab-content" style="padding-top: 1rem;">
                        <div class="attack-cookbook">
                            <h4>🐍 Fragmentation manuelle</h4>
                            <pre><code>from scapy.all import *

target = "{7}"
payload = "GET /evil HTTP/1.1\\r\\nHost: test\\r\\n\\r\\n"

# Créer des fragments de 8 bytes
frags = fragment(IP(dst=target)/TCP(dport=80)/payload, fragsize=8)

for f in frags:
    send(f, verbose=0)
print(f"Envoyé {{len(frags)}} fragments")</code><button class="copy-btn" onclick="copyCode(this)">Copy</button></pre>

                            <h4>🎭 TTL manipulation</h4>
                            <pre><code>from scapy.all import *

# Paquets avec TTL variable (évite certaines signatures)
for ttl in [1, 5, 64, 128, 255]:
    pkt = IP(dst="{7}", ttl=ttl)/TCP(dport=80, flags="S")
    send(pkt, verbose=0)</code><button class="copy-btn" onclick="copyCode(this)">Copy</button></pre>
                        </div>
                    </div>

                    <div id="hping" class="tab-content" style="padding-top: 1rem;">
                        <div class="attack-cookbook">
                            <h4>⚡ Hping3 scans</h4>
                            <pre><code># SYN scan avec fragmentation
sudo hping3 -S -f -p 80 {7}

# Timing aléatoire
sudo hping3 -S -p 80 --rand-dest -i u10000 {7}

# Spoof source
sudo hping3 -S -a 10.0.0.1 -p 80 {7}</code><button class="copy-btn" onclick="copyCode(this)">Copy</button></pre>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Sidebar -->
        <div class="sidebar">
            <!-- System Info -->
            <div class="card">
                <div class="card-header">
                    <h2>🖥️ Système</h2>
                </div>
                <div class="card-body">
                    <p style="font-size: 0.85rem; margin-bottom: 0.5rem;">
                        <strong>Docker:</strong>
                        <span class="status-badge {8}">{9}</span>
                    </p>

                    <h4 style="font-size: 0.8rem; color: var(--text-secondary); margin: 1rem 0 0.5rem;">Réseaux Docker</h4>
                    <table style="font-size: 0.8rem;">
                        <tr><th>Network</th><th>ID</th><th>Driver</th></tr>
                        {10}
                    </table>

                    <h4 style="font-size: 0.8rem; color: var(--text-secondary); margin: 1rem 0 0.5rem;">Interfaces Bridge</h4>
                    <table style="font-size: 0.8rem;">
                        <tr><th>Interface</th><th>IP/CIDR</th></tr>
                        {11}
                    </table>
                </div>
            </div>

            <!-- Quick Links -->
            <div class="card">
                <div class="card-header">
                    <h2>🔗 Accès rapides</h2>
                </div>
                <div class="card-body">
                    <div class="quick-links">
                        <a href="http://localhost:8081" target="_blank">📝 Snort Editor</a>
                        <a href="http://localhost:8082" target="_blank">📝 Suricata Editor</a>
                        <a href="http://localhost:8083" target="_blank">📝 Zeek Editor</a>
                        <a href="http://localhost:5636" target="_blank">📊 EveBox</a>
                    </div>
                </div>
            </div>

            <!-- Services -->
            <div class="card">
                <div class="card-header">
                    <h2>⚙️ Services auxiliaires</h2>
                </div>
                <div class="card-body">
                    <table style="font-size: 0.8rem;">
                        <tr><th>Container</th><th>IP</th><th>Status</th><th></th></tr>
                        {12}
                    </table>
                </div>
            </div>

            <!-- Help -->
            <div class="card">
                <div class="card-header">
                    <h2>💡 Aide rapide</h2>
                </div>
                <div class="card-body">
                    <div class="info-callout">
                        <strong>Workflow:</strong><br>
                        1. Démarrer un lab (snort/suricata/zeek)<br>
                        2. Choisir un niveau de sécurité<br>
                        3. Lancer un scan nmap sur la cible<br>
                        4. Observer les alertes (EveBox/logs)<br>
                        5. Tester les techniques d'évasion<br>
                        6. Comparer les résultats
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script src="/static/js/dashboard.js"></script>
</body>
</html>"##,
        if docker_ok { "ok" } else { "error" },
        if docker_ok { "Docker OK" } else { "Docker Error" },
        ids_rows,
        target_rows,
        snort_level,
        suricata_level,
        zeek_level,
        suricata_target,  // Used in cookbook
        if docker_ok { "ok" } else { "error" },
        if docker_ok { "OK" } else { "Erreur" },
        network_html,
        interfaces_html,
        service_rows
    );

    Html(html)
}

// ============================================================================
// PAGE DE CONFIGURATION
// ============================================================================
// Guide d'installation interactif avec:
// - Vérification du status Docker
// - Instructions pour configurer les permissions
// - Commandes utiles pour le dépannage

/// Génère la page du guide d'installation.
/// Affiche le status Docker et les instructions de configuration.
async fn setup_page() -> Html<String> {
    let (docker_ok, docker_msg) = check_docker_permissions();
    let username = std::env::var("USER").unwrap_or_else(|_| "user".into());

    let html = format!(r##"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Setup Guide - IDS Lab Commander</title>
    <link rel="stylesheet" href="/static/css/dashboard.css">
    <script src="https://unpkg.com/htmx.org@1.9.10"></script>
    <script src="https://cdn.jsdelivr.net/npm/mermaid@10/dist/mermaid.min.js"></script>
    <style>
        body {{ max-width: 900px; margin: 0 auto; padding: 2rem; }}
        .subtitle {{ color: var(--text-secondary); margin-bottom: 2rem; }}
        h2 {{ font-size: 1.25rem; margin: 2rem 0 1rem; color: var(--accent-blue); }}
        h3 {{ font-size: 1rem; margin: 1.5rem 0 0.75rem; }}
        pre {{ background: #000; padding: 1rem; border-radius: 8px; overflow-x: auto; font-size: 0.85rem; margin: 0.75rem 0; }}
        .inline-code {{ background: rgba(0,0,0,0.4); padding: 2px 6px; border-radius: 4px; }}
        .status {{ display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 0.85rem; font-weight: 500; }}
        .status.ok {{ background: rgba(34,197,94,0.2); color: var(--accent-green); }}
        .status.error {{ background: rgba(239,68,68,0.2); color: #ef4444; }}
        .warning {{ background: rgba(234,179,8,0.15); border: 1px solid rgba(234,179,8,0.3); border-radius: 8px; padding: 1rem; margin: 1rem 0; }}
        .step {{ counter-increment: step; position: relative; padding-left: 3rem; margin: 1.5rem 0; }}
        .step::before {{ content: counter(step); position: absolute; left: 0; top: 0; width: 2rem; height: 2rem; background: var(--accent-blue); border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: bold; font-size: 0.9rem; }}
        .back {{ display: inline-block; margin-bottom: 2rem; color: var(--text-secondary); text-decoration: none; }}
        .back:hover {{ color: var(--text-primary); }}
    </style>
</head>
<body>
    <a href="/" class="back">← Retour au Dashboard</a>

    <h1>🛠️ Guide d'Installation</h1>
    <p class="subtitle">Configuration complète du laboratoire IDS</p>

    <div class="card">
        <div class="card-body">
            <h3>Status actuel</h3>
            <p>Docker: <span class="status {}">{}</span></p>
            <p style="font-size: 0.85rem; color: var(--text-secondary); margin-top: 0.5rem;">{}</p>
        </div>
    </div>

    <h2>Architecture du Lab</h2>
    <div class="card">
        <div class="card-body">
            <div class="mermaid">
flowchart TB
    subgraph HOST["🖥️ Machine Hôte"]
        COMMANDER["Commander :3000"]
        NMAP["Outils Attaque<br/>nmap, scapy, hping3"]
    end

    subgraph DOCKER["🐳 Docker Networks"]
        subgraph SNORT_LAB["Snort Lab 172.28.0.0/24"]
            S_IDS["snort_ids"]
            S_TGT["target_snort"]
            S_EDIT["snort_editor :8081"]
        end

        subgraph SURI_LAB["Suricata Lab 172.29.0.0/24"]
            SU_IDS["suricata_ids"]
            SU_TGT["target_suricata"]
            SU_EDIT["suricata_editor :8082"]
            EVEBOX["evebox :5636"]
        end

        subgraph ZEEK_LAB["Zeek Lab 172.30.0.0/24"]
            Z_IDS["zeek_ids"]
            Z_TGT["target_zeek"]
            Z_EDIT["zeek_editor :8083"]
        end
    end

    NMAP --> S_TGT
    NMAP --> SU_TGT
    NMAP --> Z_TGT

    S_IDS -.-> S_TGT
    SU_IDS -.-> SU_TGT
    Z_IDS -.-> Z_TGT
            </div>
        </div>
    </div>

    <h2>1. Configuration Docker (sans sudo)</h2>

    <div class="warning">
        <strong>⚠️ Important:</strong> Pour que l'application puisse contrôler Docker, votre utilisateur doit être dans le groupe <code class="inline-code">docker</code>.
    </div>

    <div style="counter-reset: step;">
        <div class="step">
            <h3>Créer le groupe docker (si nécessaire)</h3>
            <pre><code>sudo groupadd docker</code></pre>
        </div>

        <div class="step">
            <h3>Ajouter votre utilisateur au groupe</h3>
            <pre><code>sudo usermod -aG docker {}</code></pre>
        </div>

        <div class="step">
            <h3>Appliquer les changements (sans redémarrer)</h3>
            <pre><code>newgrp docker</code></pre>
        </div>

        <div class="step">
            <h3>Vérifier les permissions</h3>
            <pre><code>docker ps</code></pre>
            <p style="font-size: 0.85rem; color: var(--text-secondary);">Si cette commande fonctionne sans sudo, c'est bon !</p>
        </div>
    </div>

    <h2>2. Permissions sudoers (optionnel)</h2>

    <p>Si vous préférez garder Docker avec sudo mais autoriser certaines commandes:</p>

    <pre><code># Éditer le fichier sudoers
sudo visudo

# Ajouter ces lignes à la fin:
{} ALL=(ALL) NOPASSWD: /usr/bin/docker
{} ALL=(ALL) NOPASSWD: /usr/bin/nmap</code></pre>

    <h2>3. Démarrage des Labs</h2>

    <div class="card">
        <div class="card-body">
            <h3>Snort Lab</h3>
            <pre><code>cd /home/rvv/Bureau/Rust.Nmap.Network/snort-lab
docker compose up -d</code></pre>
        </div>
    </div>

    <div class="card">
        <div class="card-body">
            <h3>Suricata Lab</h3>
            <pre><code>cd /home/rvv/Bureau/Rust.Nmap.Network/suricata-lab
docker compose up -d</code></pre>
        </div>
    </div>

    <div class="card">
        <div class="card-body">
            <h3>Zeek Lab</h3>
            <pre><code>cd /home/rvv/Bureau/Rust.Nmap.Network/zeek-lab
docker compose up -d</code></pre>
        </div>
    </div>

    <h2>4. Commandes utiles</h2>

    <pre><code># Voir tous les containers du lab
docker ps -a | grep -E "(snort|suricata|zeek|target|evebox)"

# Voir les logs d'un IDS
docker logs -f snort_ids
docker logs -f suricata_ids

# Redémarrer un container
docker restart suricata_ids

# Arrêter tous les labs
docker compose -f /home/rvv/Bureau/Rust.Nmap.Network/snort-lab/docker-compose.yml down
docker compose -f /home/rvv/Bureau/Rust.Nmap.Network/suricata-lab/docker-compose.yml down
docker compose -f /home/rvv/Bureau/Rust.Nmap.Network/zeek-lab/docker-compose.yml down</code></pre>

    <h2>5. Dépannage</h2>

    <div class="card">
        <div class="card-body">
            <h3>L'IDS ne démarre pas</h3>
            <pre><code># Vérifier les logs
docker logs snort_ids

# Problème de permissions
sudo chmod 666 /var/run/docker.sock</code></pre>
        </div>
    </div>

    <div class="card">
        <div class="card-body">
            <h3>Les règles ne se rechargent pas</h3>
            <pre><code># Vérifier que le reloader fonctionne
docker logs snort_reloader -f

# Forcer le rechargement manuel
docker kill -s SIGHUP snort_ids    # Snort
docker kill -s USR2 suricata_ids   # Suricata
docker restart zeek_ids            # Zeek</code></pre>
        </div>
    </div>

    <div class="card">
        <div class="card-body">
            <h3>Nmap ne voit pas la cible</h3>
            <pre><code># Vérifier que le container tourne
docker ps | grep target

# Vérifier l'IP
docker inspect target_suricata --format '{{{{range .NetworkSettings.Networks}}}}{{{{.IPAddress}}}}{{{{end}}}}'

# Tester la connectivité
ping -c 1 $(docker inspect target_suricata --format '{{{{range .NetworkSettings.Networks}}}}{{{{.IPAddress}}}}{{{{end}}}}')</code></pre>
        </div>
    </div>

    <script src="/static/js/dashboard.js"></script>
</body>
</html>"##,
        if docker_ok { "ok" } else { "error" },
        if docker_ok { "Accessible sans sudo ✓" } else { "Nécessite configuration" },
        if docker_ok { "Votre configuration Docker est correcte." } else { &docker_msg },
        username, username, username
    );

    Html(html)
}

// ============================================================================
// ACTIONS SUR LES CONTAINERS
// ============================================================================
// Ces handlers sont appelés via HTMX lors des clics sur les boutons.
// Ils utilisent Bollard pour communiquer avec l'API Docker.
// Après chaque action, ils renvoient le dashboard complet (pattern HTMX).

/// Démarre un container Docker par son ID (court ou long).
/// Appelé via POST /start/{id}
async fn start_container(Path(id): Path<String>) -> Html<String> {
    let docker = Docker::connect_with_local_defaults().unwrap();
    let _ = docker.start_container(&id, None::<StartContainerOptions<String>>).await;
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    dashboard().await
}

/// Arrête un container Docker par son ID.
/// Appelé via POST /stop/{id}
async fn stop_container(Path(id): Path<String>) -> Html<String> {
    let docker = Docker::connect_with_local_defaults().unwrap();
    let _ = docker.stop_container(&id, None::<StopContainerOptions>).await;
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    dashboard().await
}

/// Redémarre un container Docker par son ID.
/// Appelé via POST /restart/{id}
async fn restart_container(Path(id): Path<String>) -> Html<String> {
    let docker = Docker::connect_with_local_defaults().unwrap();
    let _ = docker.restart_container(&id, None).await;
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    dashboard().await
}

/// Applique un template de règles à un IDS.
/// Copie le fichier template levelX vers le fichier de règles actif.
/// Le reloader détectera le changement et rechargera l'IDS.
///
/// Arguments:
/// - ids: "snort", "suricata", ou "zeek"
/// - level: "1" à "5"
///
/// Chemins des templates:
/// - commander/templates/snort/level{1-5}_*.rules
/// - commander/templates/suricata/level{1-5}_*.rules
/// - commander/templates/zeek/level{1-5}_*.zeek
async fn apply_template(Path((ids, level)): Path<(String, String)>) -> Html<String> {
    let root = get_project_root();

    let (src_pattern, dest_file) = match ids.as_str() {
        "snort" => (format!("level{}", level), root.join("snort-lab/config/local.rules")),
        "suricata" => (format!("level{}", level), root.join("suricata-lab/rules/local.rules")),
        "zeek" => (format!("level{}", level), root.join("zeek-lab/scripts/local.zeek")),
        _ => return Html("<p>Unknown IDS</p>".to_string()),
    };

    let template_dir = root.join(format!("commander/templates/{}", ids));

    if let Ok(entries) = fs::read_dir(&template_dir) {
        for entry in entries.filter_map(|e| e.ok()) {
            let filename = entry.file_name().to_string_lossy().to_string();
            if filename.starts_with(&src_pattern) {
                if let Err(e) = fs::copy(entry.path(), &dest_file) {
                    eprintln!("Error copying template: {}", e);
                } else {
                    println!("✓ Applied {} level {} -> {:?}", ids, level, dest_file);
                }
                break;
            }
        }
    }

    dashboard().await
}

/// Récupère les 100 dernières lignes de logs d'un container.
/// Utilise l'API Docker via Bollard.
async fn get_logs(Path(id): Path<String>) -> Html<String> {
    let docker = match Docker::connect_with_local_defaults() {
        Ok(d) => d,
        Err(_) => return Html("<pre>Error connecting to Docker</pre>".to_string()),
    };

    let options = LogsOptions::<String> {
        stdout: true,
        stderr: true,
        tail: "100".to_string(),
        ..Default::default()
    };

    let mut logs = docker.logs(&id, Some(options));
    let mut output = String::new();

    while let Some(Ok(log)) = logs.next().await {
        output.push_str(&log.to_string());
    }

    Html(format!("<pre style='background:#000;padding:1rem;border-radius:8px;max-height:400px;overflow:auto;font-size:0.8rem;'>{}</pre>", output))
}

/// Réinitialise les logs d'un IDS (supprime et recrée le répertoire).
/// Utile pour repartir d'un état propre avant un test.
async fn reset_logs(Path(ids): Path<String>) -> Html<String> {
    let root = get_project_root();
    let logs_dir = match ids.as_str() {
        "suricata" => root.join("suricata-lab/logs"),
        _ => return dashboard().await,
    };

    if logs_dir.exists() {
        let _ = fs::remove_dir_all(&logs_dir);
        let _ = fs::create_dir_all(&logs_dir);
        println!("✓ Reset logs for {}", ids);
    }

    dashboard().await
}

async fn system_info() -> Html<String> {
    let bridges = get_bridge_interfaces();
    let mut html = String::from("<h3>Bridge Interfaces</h3><ul>");
    for (iface, ip) in bridges {
        html.push_str(&format!("<li><code>{}</code>: {}</li>", iface, ip));
    }
    html.push_str("</ul>");
    Html(html)
}

// ============================================================================
// GESTION DES LABS
// ============================================================================
// Ces handlers démarrent ou arrêtent un lab complet via docker compose.
// Un lab = tous les containers définis dans le docker-compose.yml du lab.

/// Démarre un lab complet via `docker compose up -d`.
/// Appelé via POST /lab/start/{lab}
///
/// Arguments:
/// - lab: "snort", "suricata", ou "zeek"
///
/// Exécute: docker compose up -d dans le répertoire {lab}-lab/
async fn start_lab(Path(lab): Path<String>) -> Html<String> {
    let root = get_project_root();
    let lab_dir = root.join(format!("{}-lab", lab));

    let output = Command::new("docker")
        .args(["compose", "up", "-d"])
        .current_dir(&lab_dir)
        .output();

    match output {
        Ok(o) => {
            if o.status.success() {
                println!("✓ Started lab: {}", lab);
            } else {
                eprintln!("Failed to start {}: {}", lab, String::from_utf8_lossy(&o.stderr));
            }
        }
        Err(e) => eprintln!("Error starting lab: {}", e),
    }

    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
    dashboard().await
}

/// Arrête un lab complet via `docker compose down`.
/// Appelé via POST /lab/stop/{lab}
async fn stop_lab(Path(lab): Path<String>) -> Html<String> {
    let root = get_project_root();
    let lab_dir = root.join(format!("{}-lab", lab));

    let output = Command::new("docker")
        .args(["compose", "down"])
        .current_dir(&lab_dir)
        .output();

    match output {
        Ok(o) => {
            if o.status.success() {
                println!("✓ Stopped lab: {}", lab);
            } else {
                eprintln!("Failed to stop {}: {}", lab, String::from_utf8_lossy(&o.stderr));
            }
        }
        Err(e) => eprintln!("Error stopping lab: {}", e),
    }

    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    dashboard().await
}
