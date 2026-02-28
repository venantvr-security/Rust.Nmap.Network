/* IDS Lab Commander - Dashboard JavaScript */

// Tab switching
function showTab(tabId) {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    document.querySelector(`[onclick="showTab('${tabId}')"]`).classList.add('active');
    document.getElementById(tabId).classList.add('active');
}

// Copy code to clipboard
function copyCode(btn) {
    const code = btn.previousSibling.textContent;
    navigator.clipboard.writeText(code).then(() => {
        btn.textContent = 'Copied!';
        btn.classList.add('copied');
        setTimeout(() => {
            btn.textContent = 'Copy';
            btn.classList.remove('copied');
        }, 1500);
    }).catch(err => {
        console.error('Failed to copy:', err);
        btn.textContent = 'Error';
    });
}

// Auto-refresh status every 3 seconds
let autoRefreshInterval = null;
let isRefreshing = false;

function startAutoRefresh() {
    if (autoRefreshInterval) return;

    autoRefreshInterval = setInterval(() => {
        // Ne pas rafraîchir si une requête HTMX est en cours
        if (isRefreshing || document.body.classList.contains('htmx-request')) return;

        isRefreshing = true;
        fetch('/api/status')
            .then(r => r.json())
            .then(data => {
                updateContainerStatus(data);
                isRefreshing = false;
            })
            .catch(() => { isRefreshing = false; });
    }, 3000);

    console.log('🔄 Auto-refresh activé (3s)');
}

function stopAutoRefresh() {
    if (autoRefreshInterval) {
        clearInterval(autoRefreshInterval);
        autoRefreshInterval = null;
        console.log('⏹️ Auto-refresh désactivé');
    }
}

// Met à jour le status des containers sans recharger la page
function updateContainerStatus(containers) {
    containers.forEach(c => {
        const row = document.querySelector(`tr[data-container="${c.name}"]`);
        if (!row) return;

        const isRunning = c.status.includes('Up');
        const statusCell = row.querySelector('td:nth-child(3)');
        const btnCell = row.querySelector('td:nth-child(4)');

        // Update row class
        row.className = isRunning ? 'running' : 'stopped';

        // Update status text (safe DOM manipulation)
        if (statusCell) {
            statusCell.textContent = '';
            const span = document.createElement('span');
            span.style.color = isRunning ? 'var(--accent-green)' : 'var(--accent-red)';
            span.textContent = isRunning ? '● Running' : '○ Stopped';
            statusCell.appendChild(span);
        }

        // Update button
        if (btnCell) {
            const btn = btnCell.querySelector('.btn:not(.neutral)');
            if (btn) {
                const shortId = c.id.substring(0, 12);
                btn.className = `btn ${isRunning ? 'stop' : 'start'}`;
                btn.setAttribute('hx-post', `/${isRunning ? 'stop' : 'start'}/${shortId}`);
                btn.textContent = isRunning ? 'Stop' : 'Start';
                htmx.process(btn); // Re-register HTMX handlers
            }
        }
    });
}

// Initialize Mermaid diagrams if present
document.addEventListener('DOMContentLoaded', function() {
    if (typeof mermaid !== 'undefined') {
        mermaid.initialize({
            startOnLoad: true,
            theme: 'dark',
            themeVariables: {
                primaryColor: '#3b82f6',
                primaryTextColor: '#f0f0f0',
                primaryBorderColor: '#1e3a5f',
                lineColor: '#888',
                secondaryColor: '#1a1a2e',
                tertiaryColor: '#0f0f1a'
            }
        });
    }

    // Start auto-refresh
    startAutoRefresh();
});

// HTMX event handlers
document.body.addEventListener('htmx:afterSwap', function(event) {
    // Re-initialize mermaid after HTMX swap
    if (typeof mermaid !== 'undefined') {
        mermaid.init(undefined, document.querySelectorAll('.mermaid'));
    }
});

// Keyboard shortcuts
document.addEventListener('keydown', function(e) {
    // Ctrl+1: Snort lab
    if (e.ctrlKey && e.key === '1') {
        e.preventDefault();
        document.querySelector('[hx-post="/lab/start/snort"]')?.click();
    }
    // Ctrl+2: Suricata lab
    if (e.ctrlKey && e.key === '2') {
        e.preventDefault();
        document.querySelector('[hx-post="/lab/start/suricata"]')?.click();
    }
    // Ctrl+3: Zeek lab
    if (e.ctrlKey && e.key === '3') {
        e.preventDefault();
        document.querySelector('[hx-post="/lab/start/zeek"]')?.click();
    }
});

// Toast notifications
function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    toast.style.cssText = `
        position: fixed;
        bottom: 2rem;
        right: 2rem;
        padding: 1rem 1.5rem;
        border-radius: 8px;
        background: ${type === 'success' ? '#22c55e' : type === 'error' ? '#ef4444' : '#3b82f6'};
        color: white;
        font-weight: 500;
        z-index: 9999;
        animation: slideIn 0.3s ease;
    `;
    document.body.appendChild(toast);

    setTimeout(() => {
        toast.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => toast.remove(), 300);
    }, 3000);
}

// Add animation styles
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
    @keyframes slideOut {
        from { transform: translateX(0); opacity: 1; }
        to { transform: translateX(100%); opacity: 0; }
    }
    .copy-btn.copied {
        background: #22c55e !important;
    }
`;
document.head.appendChild(style);

// =============================================================================
// ALERTS VIEWER
// =============================================================================

let currentAlertTab = 'snort';

// Switch between alert tabs
function showAlertTab(ids) {
    // Update tab buttons
    document.querySelectorAll('.tabs .tab').forEach(t => t.classList.remove('active'));
    event.target.classList.add('active');

    // Update panels
    document.querySelectorAll('.alerts-panel').forEach(p => p.classList.remove('active'));
    document.getElementById(`alerts-${ids}`).classList.add('active');

    currentAlertTab = ids;
    loadAlerts(ids);
}

// Load alerts for a specific IDS
function loadAlerts(ids) {
    const contentEl = document.getElementById(`alerts-content-${ids}`);
    if (!contentEl) return;

    contentEl.textContent = 'Chargement...';
    contentEl.className = 'alerts-content loading';

    fetch(`/api/alerts/${ids}`)
        .then(r => r.json())
        .then(data => {
            if (data.error) {
                contentEl.textContent = `Erreur: ${data.error}\n\nAssurez-vous que le container ${ids}_ids est en cours d'exécution.`;
                contentEl.className = 'alerts-content error';
                return;
            }

            if (data.alerts.length === 0) {
                contentEl.textContent = `Aucune alerte détectée.\n\nLancez un scan sur la cible pour générer des alertes:\nnmap -sS -p 21,22,80 <target_ip>`;
                contentEl.className = 'alerts-content';
                return;
            }

            // Format alerts with syntax highlighting
            const formatted = data.alerts.map(line => {
                // Highlight based on severity/keywords
                if (line.includes('Priority: 1') || line.includes('CRITICAL') || line.includes('high')) {
                    return `<span class="alert-priority-high">${escapeHtml(line)}</span>`;
                } else if (line.includes('Priority: 2') || line.includes('WARNING') || line.includes('medium')) {
                    return `<span class="alert-priority-medium">${escapeHtml(line)}</span>`;
                } else {
                    return `<span class="alert-line">${escapeHtml(line)}</span>`;
                }
            }).join('\n');

            contentEl.innerHTML = formatted;
            contentEl.className = 'alerts-content';
        })
        .catch(err => {
            contentEl.textContent = `Erreur de connexion: ${err.message}`;
            contentEl.className = 'alerts-content error';
        });
}

// Refresh all alerts
function refreshAlerts() {
    loadAlerts(currentAlertTab);
}

// Escape HTML to prevent XSS
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Auto-load alerts when page loads (if a lab is running)
document.addEventListener('DOMContentLoaded', function() {
    // Delay to let other initializations complete
    setTimeout(() => {
        loadAlerts('snort');
    }, 1000);
});
