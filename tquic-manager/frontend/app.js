// TQUIC Manager Frontend JavaScript

const API_BASE = window.location.origin;
let refreshInterval;

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    initializeApp();
});

async function initializeApp() {
    await fetchStatus();
    setupEventListeners();
    startAutoRefresh();
}

function setupEventListeners() {
    const masterToggle = document.getElementById('masterToggle');
    masterToggle.addEventListener('change', handleMasterToggle);
}

async function fetchStatus() {
    try {
        const response = await fetch(`${API_BASE}/api/status`);
        const data = await response.json();

        if (data.success) {
            updateUI(data);
            updateLastRefreshTime();
        }
    } catch (error) {
        console.error('Failed to fetch status:', error);
        showToast('Failed to connect to backend', 'error');
    }
}

function updateUI(data) {
    // Update master toggle
    const masterToggle = document.getElementById('masterToggle');
    const masterStatus = document.getElementById('masterStatus');

    masterToggle.checked = data.enabled;
    masterStatus.textContent = data.enabled ? 'ON' : 'OFF';
    masterStatus.className = `status-badge ${data.enabled ? 'enabled' : 'disabled'}`;

    // Update status cards
    document.getElementById('tquicState').textContent = data.enabled ? '✅ Enabled' : '❌ Disabled';
    document.getElementById('ccAlgorithm').textContent =
        data.settings['net.tquic.cc_algorithm'] || data.settings['net.tquic.congestion'] || '-';

    // Update modules list
    updateModulesList(data.modules);

    // Update settings
    updateSettings(data.settings);
}

function updateModulesList(modules) {
    const modulesList = document.getElementById('modulesList');

    if (!modules || modules.length === 0) {
        modulesList.innerHTML = '<p>No TQUIC modules loaded</p>';
        return;
    }

    modulesList.innerHTML = modules
        .map(mod => `<div class="module-item">${mod.name} (${mod.size} bytes)</div>`)
        .join('');
}

function updateSettings(settings) {
    // Categorize settings
    const categories = {
        core: ['enabled', 'debug_level', 'cc_algorithm', 'congestion', 'cc_coupled'],
        network: ['idle_timeout_ms', 'default_ack_delay_us', 'ack_frequency_enabled',
            'additional_addresses_enabled', 'additional_addresses_max', 'ecn_enabled'],
        performance: ['initial_cwnd_packets', 'initial_rtt_ms', 'burst_limit',
            'bbr_rtt_threshold_ms', 'ecn_beta'],
        security: ['cert_verify_mode', 'cert_verify_hostname', 'cert_revocation_mode',
            'cert_time_tolerance', 'cookie_lifetime_ms', 'attack_threshold']
    };

    // Populate each category
    for (const [category, keys] of Object.entries(categories)) {
        const container = document.getElementById(`${category}Settings`);
        container.innerHTML = '';

        for (const key of keys) {
            const fullKey = `net.tquic.${key}`;
            if (fullKey in settings) {
                const settingElement = createSettingElement(fullKey, settings[fullKey]);
                container.appendChild(settingElement);
            }
        }
    }
}

function createSettingElement(key, value) {
    const div = document.createElement('div');
    div.className = 'setting-item';

    const label = document.createElement('label');
    label.className = 'setting-label';
    label.textContent = key.replace('net.tquic.', '');

    const input = document.createElement('input');
    input.className = 'setting-input';
    input.type = typeof value === 'number' ? 'number' : 'text';
    input.value = value;
    input.dataset.key = key;

    // Add change handler with debouncing
    let timeout;
    input.addEventListener('change', (e) => {
        clearTimeout(timeout);
        timeout = setTimeout(() => {
            updateSetting(key, e.target.value);
        }, 500);
    });

    div.appendChild(label);
    div.appendChild(input);

    return div;
}

async function handleMasterToggle(e) {
    const enabled = e.target.checked;

    try {
        const response = await fetch(`${API_BASE}/api/toggle`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ enabled })
        });

        const data = await response.json();

        if (data.success) {
            showToast(`TQUIC ${enabled ? 'enabled' : 'disabled'} successfully`, 'success');
            await fetchStatus();
        } else {
            showToast(`Failed to toggle TQUIC: ${data.error}`, 'error');
            e.target.checked = !enabled; // Revert toggle
        }
    } catch (error) {
        showToast('Failed to toggle TQUIC', 'error');
        e.target.checked = !enabled; // Revert toggle
    }
}

async function updateSetting(key, value) {
    try {
        const response = await fetch(`${API_BASE}/api/settings`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ key, value })
        });

        const data = await response.json();

        if (data.success) {
            showToast(`Updated ${key.replace('net.tquic.', '')}`, 'success');
        } else {
            showToast(`Failed to update: ${data.error}`, 'error');
            await fetchStatus(); // Revert to actual value
        }
    } catch (error) {
        showToast('Failed to update setting', 'error');
        await fetchStatus(); // Revert to actual value
    }
}

function showToast(message, type = 'success') {
    const toast = document.getElementById('toast');
    toast.textContent = message;
    toast.className = `toast ${type} show`;

    setTimeout(() => {
        toast.className = 'toast';
    }, 3000);
}

function updateLastRefreshTime() {
    const now = new Date();
    document.getElementById('lastUpdate').textContent = now.toLocaleTimeString();
}

function startAutoRefresh() {
    refreshInterval = setInterval(() => {
        fetchStatus();
    }, 5000); // Refresh every 5 seconds
}

function stopAutoRefresh() {
    if (refreshInterval) {
        clearInterval(refreshInterval);
    }
}

// Stop refresh when page is hidden
document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
        stopAutoRefresh();
    } else {
        startAutoRefresh();
    }
});
