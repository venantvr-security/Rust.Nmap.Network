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

// Auto-refresh status every 30 seconds
let autoRefreshInterval = null;

function startAutoRefresh() {
    autoRefreshInterval = setInterval(() => {
        htmx.trigger(document.body, 'refresh');
    }, 30000);
}

function stopAutoRefresh() {
    if (autoRefreshInterval) {
        clearInterval(autoRefreshInterval);
        autoRefreshInterval = null;
    }
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
    // startAutoRefresh();
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
