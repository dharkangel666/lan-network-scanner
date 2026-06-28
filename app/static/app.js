const hostsBody = document.getElementById("hosts-body");
const portsBody = document.getElementById("ports-body");
const networkInfo = document.getElementById("network-info");
const discoveryStatus = document.getElementById("discovery-status");
const portStatus = document.getElementById("port-status");
const scanNetworkBtn = document.getElementById("scan-network-btn");
const stopDiscoveryBtn = document.getElementById("stop-discovery-btn");
const restoreLastScanBtn = document.getElementById("restore-last-scan-btn");
const scanPortsBtn = document.getElementById("scan-ports-btn");
const stopPortScanBtn = document.getElementById("stop-port-scan-btn");
const portScanForm = document.getElementById("port-scan-form");
const targetHostInput = document.getElementById("target-host");
const targetPortsPreset = document.getElementById("target-ports-preset");
const targetPortsCustom = document.getElementById("target-ports-custom");
const setupNotice = document.getElementById("setup-notice");
const setupMessage = document.getElementById("setup-message");
const setupCommand = document.getElementById("setup-command");
const portModal = document.getElementById("port-modal");
const portModalBackdrop = document.getElementById("port-modal-backdrop");
const portModalClose = document.getElementById("port-modal-close");
const portModalTitle = document.getElementById("port-modal-title");
const portModalService = document.getElementById("port-modal-service");
const portModalDescription = document.getElementById("port-modal-description");
const portModalUse = document.getElementById("port-modal-use");
const portModalRisk = document.getElementById("port-modal-risk");
const portModalBannerWrap = document.getElementById("port-modal-banner-wrap");
const portModalBanner = document.getElementById("port-modal-banner");
const portModalConnect = document.getElementById("port-modal-connect");
const portModalConnectActions = document.getElementById("port-modal-connect-actions");
const portModalConnectNote = document.getElementById("port-modal-connect-note");
const portMonitorTitle = document.getElementById("port-monitor-title");
const portMonitorStopBtn = document.getElementById("port-monitor-stop-btn");
const portMonitorPanel = document.getElementById("port-monitor-panel");
const portMonitorStatus = document.getElementById("port-monitor-status");
const portMonitorStats = document.getElementById("port-monitor-stats");
const portMonitorLog = document.getElementById("port-monitor-log");
const discoverySummary = document.getElementById("discovery-summary");
const infrastructurePanel = document.getElementById("infrastructure-panel");
const infrastructureGrid = document.getElementById("infrastructure-grid");
const infrastructureSubtitle = document.getElementById("infrastructure-subtitle");
const hostsToolbar = document.getElementById("hosts-toolbar");
const hostsFilterInput = document.getElementById("hosts-filter");
const hostsFilterCount = document.getElementById("hosts-filter-count");
const exportHostsCsvBtn = document.getElementById("export-hosts-csv");
const exportHostsJsonBtn = document.getElementById("export-hosts-json");
const starlinkPanel = document.getElementById("starlink-panel");
const starlinkSubtitle = document.getElementById("starlink-subtitle");
const starlinkStatusBadge = document.getElementById("starlink-status-badge");
const starlinkStats = document.getElementById("starlink-stats");
const portProfileStatus = document.getElementById("port-profile-status");
const loadPortProfileBtn = document.getElementById("load-port-profile-btn");
const savePortProfileBtn = document.getElementById("save-port-profile-btn");
const clearPortProfileBtn = document.getElementById("clear-port-profile-btn");
const copyToast = document.getElementById("copy-toast");
const themeToggleBtn = document.getElementById("theme-toggle");
const autoRescanSelect = document.getElementById("auto-rescan-interval");
const autoRescanStatus = document.getElementById("auto-rescan-status");
const notifyNewDevicesCheckbox = document.getElementById("notify-new-devices");
const notifyStatus = document.getElementById("notify-status");
const topologyPanel = document.getElementById("topology-panel");
const topologyView = document.getElementById("topology-view");
const topologySubtitle = document.getElementById("topology-subtitle");
const servicesStatus = document.getElementById("services-status");
const servicesSummary = document.getElementById("services-summary");
const servicesHostsBody = document.getElementById("services-hosts-body");
const certificatesBody = document.getElementById("certificates-body");
const refreshServicesBtn = document.getElementById("refresh-services-btn");
const serviceModal = document.getElementById("service-modal");
const serviceModalBackdrop = document.getElementById("service-modal-backdrop");
const serviceModalClose = document.getElementById("service-modal-close");
const serviceModalTitle = document.getElementById("service-modal-title");
const serviceModalRole = document.getElementById("service-modal-role");
const serviceModalContent = document.getElementById("service-modal-content");
const portModalCertWrap = document.getElementById("port-modal-cert-wrap");
const portModalCertSubject = document.getElementById("port-modal-cert-subject");
const portModalCertMeta = document.getElementById("port-modal-cert-meta");

const UI_PREFS_KEY = "lan-network-scanner-ui";

let uiPrefs = {
  scrollToPortScanner: true,
  theme: "dark",
  autoRescanMinutes: 0,
  notifyNewDevices: false,
};

let discoverySource = null;
let portSource = null;
let monitorSource = null;
let activeMonitorPort = null;
let hostCount = 0;
let openPortCount = 0;
let discoveredHosts = [];
let hostSort = { column: "ip", direction: "asc" };
let hostFilterQuery = "";
let lastScanSummary = null;
let lastStarlinkSummary = null;
let currentPortProfile = null;
let selectedHostIp = null;
let copyToastTimer = null;
let lastScanAvailable = false;
let autoRescanTimer = null;
let autoRescanCountdownTimer = null;
let autoRescanNextAt = null;
let networkMeta = null;

const CONNECTION_SORT_ORDER = {
  ethernet: 0,
  wifi: 1,
  unknown: 2,
};

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function loadUiPrefs() {
  try {
    const stored = JSON.parse(localStorage.getItem(UI_PREFS_KEY) || "{}");
    if (stored.hostSort?.column) {
      hostSort = {
        column: stored.hostSort.column,
        direction: stored.hostSort.direction === "desc" ? "desc" : "asc",
      };
    }
    if (typeof stored.scrollToPortScanner === "boolean") {
      uiPrefs.scrollToPortScanner = stored.scrollToPortScanner;
    }
    if (stored.theme === "light" || stored.theme === "dark") {
      uiPrefs.theme = stored.theme;
    }
    if (Number.isFinite(stored.autoRescanMinutes)) {
      uiPrefs.autoRescanMinutes = Math.max(0, Number(stored.autoRescanMinutes));
    }
    if (typeof stored.notifyNewDevices === "boolean") {
      uiPrefs.notifyNewDevices = stored.notifyNewDevices;
    }
  } catch {
    // Ignore invalid saved preferences.
  }
  applyTheme(uiPrefs.theme, false);
  if (autoRescanSelect) {
    autoRescanSelect.value = String(uiPrefs.autoRescanMinutes || 0);
  }
  if (notifyNewDevicesCheckbox) {
    notifyNewDevicesCheckbox.checked = uiPrefs.notifyNewDevices;
  }
}

function saveUiPrefs() {
  try {
    localStorage.setItem(
      UI_PREFS_KEY,
      JSON.stringify({
        hostSort,
        scrollToPortScanner: uiPrefs.scrollToPortScanner,
        theme: uiPrefs.theme,
        autoRescanMinutes: uiPrefs.autoRescanMinutes,
        notifyNewDevices: uiPrefs.notifyNewDevices,
      }),
    );
  } catch {
    // Ignore storage errors (private browsing, quota, etc.).
  }
}

function applyTheme(theme, persist = true) {
  const resolved = theme === "light" ? "light" : "dark";
  document.documentElement.dataset.theme = resolved;
  uiPrefs.theme = resolved;
  if (themeToggleBtn) {
    themeToggleBtn.textContent = resolved === "light" ? "Dark mode" : "Light mode";
    themeToggleBtn.setAttribute(
      "aria-label",
      resolved === "light" ? "Switch to dark mode" : "Switch to light mode",
    );
  }
  if (persist) {
    saveUiPrefs();
  }
}

function toggleTheme() {
  applyTheme(uiPrefs.theme === "light" ? "dark" : "light");
}

function clearAutoRescanTimers() {
  if (autoRescanTimer) {
    clearTimeout(autoRescanTimer);
    autoRescanTimer = null;
  }
  if (autoRescanCountdownTimer) {
    clearInterval(autoRescanCountdownTimer);
    autoRescanCountdownTimer = null;
  }
  autoRescanNextAt = null;
}

function updateAutoRescanStatus() {
  if (!autoRescanStatus) {
    return;
  }
  const minutes = Number(uiPrefs.autoRescanMinutes) || 0;
  if (!minutes) {
    autoRescanStatus.textContent = "";
    return;
  }
  if (discoverySource) {
    autoRescanStatus.textContent = "Refresh after current scan";
    return;
  }
  if (!autoRescanNextAt) {
    autoRescanStatus.textContent = "";
    return;
  }
  const remainingMs = Math.max(0, autoRescanNextAt - Date.now());
  const remainingMin = Math.max(1, Math.ceil(remainingMs / 60000));
  autoRescanStatus.textContent = `Next in ~${remainingMin} min`;
}

function scheduleAutoRescan() {
  clearAutoRescanTimers();
  const minutes = Number(uiPrefs.autoRescanMinutes) || 0;
  if (!minutes) {
    updateAutoRescanStatus();
    return;
  }

  autoRescanNextAt = Date.now() + minutes * 60 * 1000;
  autoRescanTimer = setTimeout(() => {
    if (!discoverySource) {
      startDiscoveryScan({ auto: true });
    } else {
      scheduleAutoRescan();
    }
  }, minutes * 60 * 1000);
  autoRescanCountdownTimer = setInterval(updateAutoRescanStatus, 10000);
  updateAutoRescanStatus();
}

function formatNewDeviceNotification() {
  const newHosts = discoveredHosts.filter((host) => host.scan_change === "new");
  if (!newHosts.length) {
    return null;
  }
  const title =
    newHosts.length === 1
      ? "New device on network"
      : `${newHosts.length} new devices on network`;
  const lines = newHosts.slice(0, 5).map((host) => {
    const label =
      host.hostname && host.hostname !== "—"
        ? host.hostname
        : host.vendor || "Unknown device";
    return `${host.ip} (${label})`;
  });
  if (newHosts.length > 5) {
    lines.push(`+${newHosts.length - 5} more`);
  }
  return { title, body: lines.join("\n") };
}

async function notifyNewDevicesIfNeeded() {
  if (!uiPrefs.notifyNewDevices) {
    return;
  }
  if (!lastScanSummary || lastScanSummary.first_scan || !lastScanSummary.new_count) {
    return;
  }

  const payload = formatNewDeviceNotification();
  if (!payload) {
    return;
  }

  if (typeof Notification !== "undefined" && Notification.permission === "granted") {
    new Notification(payload.title, {
      body: payload.body,
      tag: "lan-network-scanner-new-device",
    });
  }

  try {
    await fetch("/api/notify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
  } catch {
    // Desktop notifications are optional.
  }
}

async function updateNotifyStatus() {
  if (!notifyStatus) {
    return;
  }
  if (!uiPrefs.notifyNewDevices) {
    notifyStatus.textContent = "";
    return;
  }

  const channels = [];
  if (typeof Notification !== "undefined") {
    if (Notification.permission === "granted") {
      channels.push("browser");
    } else if (Notification.permission === "denied") {
      channels.push("browser blocked");
    }
  }

  try {
    const response = await fetch("/api/notify/status");
    if (response.ok) {
      const data = await response.json();
      if (data.available) {
        channels.push("desktop");
      }
    }
  } catch {
    // Ignore status lookup errors.
  }

  if (!channels.length) {
    notifyStatus.textContent = "Allow browser alerts or install notify-send";
    return;
  }
  notifyStatus.textContent = `Via ${channels.join(" + ")}`;
}

async function enableDeviceNotifications() {
  uiPrefs.notifyNewDevices = true;
  if (notifyNewDevicesCheckbox) {
    notifyNewDevicesCheckbox.checked = true;
  }
  saveUiPrefs();

  if (typeof Notification !== "undefined" && Notification.permission === "default") {
    await Notification.requestPermission();
  }
  await updateNotifyStatus();
}

function showCopyToast(message) {
  if (!copyToast) {
    return;
  }
  copyToast.textContent = message;
  copyToast.classList.remove("hidden");
  if (copyToastTimer) {
    clearTimeout(copyToastTimer);
  }
  copyToastTimer = setTimeout(() => {
    copyToast.classList.add("hidden");
  }, 1600);
}

async function copyToClipboard(value, label = "Copied") {
  const text = String(value ?? "").trim();
  if (!text || text === "—") {
    return;
  }
  try {
    await navigator.clipboard.writeText(text);
    showCopyToast(`${label}: ${text}`);
  } catch {
    window.prompt("Copy this value:", text);
  }
}

function attachCopyableCell(cell, value, label) {
  if (!cell || !value || value === "—") {
    return;
  }
  cell.classList.add("copyable-cell");
  cell.title = `Click to copy ${label}`;
  cell.addEventListener("click", (event) => {
    event.stopPropagation();
    copyToClipboard(value, label);
  });
}

function scrollToPortScannerPanel() {
  if (!uiPrefs.scrollToPortScanner || !portScanForm) {
    return;
  }
  portScanForm.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function looksLikeIpv4(query) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(query);
}

function hostMatchesFilter(host, query) {
  if (!query) {
    return true;
  }
  if (looksLikeIpv4(query)) {
    return String(host.ip || "").toLowerCase() === query;
  }
  const haystack = [
    host.ip,
    host.hostname,
    host.mac,
    host.vendor,
    host.os,
    host.connection_label,
    host.connection_detail,
    host.device_role,
    host.infra_role_labels,
    host.starlink_name,
    host.starlink_band,
    host.starlink_signal_dbm,
    host.starlink_snr,
    host.scan_change,
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
  return haystack.includes(query);
}

function getVisibleHosts() {
  const query = hostFilterQuery.trim().toLowerCase();
  const filtered = query
    ? discoveredHosts.filter((host) => hostMatchesFilter(host, query))
    : discoveredHosts.slice();
  return filtered.sort((left, right) => {
    const result = compareHosts(left, right, hostSort.column);
    return hostSort.direction === "asc" ? result : -result;
  });
}

function updateHostsToolbar() {
  const hasHosts = discoveredHosts.length > 0;
  hostsToolbar.classList.toggle("hidden", !hasHosts);
  exportHostsCsvBtn.disabled = !hasHosts;
  exportHostsJsonBtn.disabled = !hasHosts;

  if (!hasHosts) {
    hostsFilterCount.textContent = "";
    return;
  }

  const visibleCount = getVisibleHosts().length;
  if (hostFilterQuery.trim()) {
    hostsFilterCount.textContent = `${visibleCount} of ${discoveredHosts.length}`;
  } else {
    hostsFilterCount.textContent = `${discoveredHosts.length} host${discoveredHosts.length === 1 ? "" : "s"}`;
  }
}

function renderInfrastructurePanel(infrastructure) {
  if (!infrastructurePanel || !infrastructureGrid) {
    return;
  }

  const services = infrastructure?.services || [];
  if (!services.length) {
    infrastructurePanel.classList.add("hidden");
    infrastructureGrid.innerHTML = "";
    return;
  }

  infrastructurePanel.classList.remove("hidden");
  const parts = [];
  if (infrastructure.domain) {
    parts.push(`Domain: ${infrastructure.domain}`);
  }
  if (infrastructure.configured_dns?.length) {
    parts.push(`Resolver: ${infrastructure.configured_dns.join(", ")}`);
  }
  infrastructureSubtitle.textContent = parts.join(" · ");

  infrastructureGrid.innerHTML = services
    .map((service) => {
      const label = service.label || service.role || "Service";
      const ip = service.ip || "—";
      const hostLabel = service.hostname || service.vendor || "";
      const confidence = service.confidence ? ` (${service.confidence})` : "";
      const detail = service.detail ? ` — ${service.detail}` : "";
      return `
        <article class="infrastructure-card infrastructure-${escapeHtml(service.role || "service")}">
          <span class="infrastructure-card-label">${escapeHtml(label)}</span>
          <span class="infrastructure-card-ip mono">${escapeHtml(ip)}</span>
          ${hostLabel ? `<span class="infrastructure-card-host">${escapeHtml(hostLabel)}</span>` : ""}
          <span class="infrastructure-card-meta">${escapeHtml(`${confidence}${detail}`.trim())}</span>
        </article>
      `;
    })
    .join("");
}

function formatInfraRoles(host) {
  const roles = host.infra_roles || [];
  if (!roles.length) {
    return '<span class="infra-role missing">—</span>';
  }
  return roles
    .map((role) => {
      const label = role.label || role.role || "Role";
      const confidence = role.confidence ? ` (${role.confidence})` : "";
      const detail = role.detail ? ` — ${role.detail}` : "";
      const title = `${label}${confidence}${detail}`.replaceAll('"', "&quot;");
      return `<span class="infra-role infra-role-${escapeHtml(role.role || "other")}" title="${title}">${escapeHtml(label)}</span>`;
    })
    .join(" ");
}

function renderDiscoverySummary(summary) {
  if (!summary) {
    discoverySummary.classList.add("hidden");
    discoverySummary.innerHTML = "";
    renderInfrastructurePanel(null);
    return;
  }

  renderInfrastructurePanel(summary.infrastructure);

  if (summary.first_scan) {
    discoverySummary.innerHTML =
      "<strong>First scan saved.</strong> Run another scan to see new and disappeared devices.";
    discoverySummary.classList.remove("hidden");
    return;
  }

  const parts = [];
  if (summary.new_count > 0) {
    parts.push(`<strong>${summary.new_count}</strong> new since last scan`);
  } else {
    parts.push("No new devices since last scan");
  }
  if (summary.previous_scan_at) {
    parts.push(`(previous: ${escapeHtml(summary.previous_scan_at)})`);
  }

  let html = parts.join(" ");
  if (summary.disappeared?.length) {
    const items = summary.disappeared
      .map((host) => {
        const label = host.hostname || host.ip;
        return `<li>${escapeHtml(label)} <span class="muted">(${escapeHtml(host.ip)})</span></li>`;
      })
      .join("");
    html += `<ul class="disappeared-list">${items}</ul>`;
  }
  discoverySummary.innerHTML = html;
  discoverySummary.classList.remove("hidden");
}

function renderStarlinkStat(label, value) {
  return `
    <div class="starlink-stat">
      <span class="starlink-stat-label">${escapeHtml(label)}</span>
      <span class="starlink-stat-value">${escapeHtml(value)}</span>
    </div>
  `;
}

function renderStarlinkPanel(summary) {
  if (!summary?.available) {
    starlinkPanel.classList.add("hidden");
    return;
  }

  lastStarlinkSummary = summary;
  starlinkPanel.classList.remove("hidden");
  starlinkStatusBadge.textContent = "Live";
  starlinkStatusBadge.classList.remove("offline");

  const routerLabel = summary.router_host ? `Router ${summary.router_host}` : "Starlink router";
  starlinkSubtitle.textContent = routerLabel;

  const stats = [
    renderStarlinkStat("Clients", summary.client_count ?? 0),
    renderStarlinkStat("Wi-Fi", summary.wifi_clients ?? 0),
    renderStarlinkStat("Ethernet", summary.ethernet_clients ?? 0),
    renderStarlinkStat("2.4 GHz", summary.wifi_2_4ghz ?? 0),
    renderStarlinkStat("5 GHz", summary.wifi_5ghz ?? 0),
  ];

  if (summary.avg_snr != null) {
    stats.push(renderStarlinkStat("Avg SNR", `${summary.avg_snr} dB`));
  }
  if (summary.avg_signal_dbm != null) {
    stats.push(renderStarlinkStat("Avg signal", `${summary.avg_signal_dbm} dBm`));
  }
  if (summary.weak_signal_clients != null) {
    stats.push(renderStarlinkStat("Weak signal", summary.weak_signal_clients));
  }
  if (summary.scanned_hosts > 0) {
    stats.push(
      renderStarlinkStat(
        "Matched scan",
        `${summary.matched_in_scan ?? 0}/${summary.scanned_hosts}`,
      ),
    );
  }

  starlinkStats.innerHTML = stats.join("");
}

function showStarlinkUnavailable(starlink) {
  if (!starlink || starlink.available) {
    return;
  }
  starlinkPanel.classList.remove("hidden");
  starlinkStatusBadge.textContent = "Unavailable";
  starlinkStatusBadge.classList.add("offline");
  starlinkSubtitle.textContent = starlink.error || "Starlink router data not available";
  starlinkStats.innerHTML = renderStarlinkStat(
    "Setup",
    "Run Starlink Setup from your desktop",
  );
}

function formatStarlinkSignal(host) {
  if (host.connection_source !== "starlink") {
    return '<span class="starlink-signal missing">—</span>';
  }

  if (host.connection === "ethernet") {
    const detail = host.starlink_band || host.connection_detail || "Wired";
    return `<span class="starlink-signal wired">${escapeHtml(detail)}</span>`;
  }

  const parts = [];
  if (host.starlink_band) {
    parts.push(host.starlink_band);
  }
  if (host.starlink_signal_dbm != null) {
    parts.push(`${host.starlink_signal_dbm} dBm`);
  }
  if (host.starlink_snr != null) {
    parts.push(`SNR ${host.starlink_snr}`);
  }

  const label = parts.length ? parts.join(" · ") : host.connection_detail || "Wi-Fi";
  let qualityClass = "fair";
  if (host.starlink_signal_dbm != null) {
    if (host.starlink_signal_dbm >= -55) {
      qualityClass = "good";
    } else if (host.starlink_signal_dbm < -70) {
      qualityClass = "weak";
    }
  } else if (host.starlink_snr != null) {
    if (host.starlink_snr >= 35) {
      qualityClass = "good";
    } else if (host.starlink_snr < 20) {
      qualityClass = "weak";
    }
  }

  const titleParts = [];
  if (host.starlink_name) {
    titleParts.push(host.starlink_name);
  }
  if (host.starlink_channel_mhz) {
    titleParts.push(`${host.starlink_channel_mhz} MHz channel`);
  }
  if (host.starlink_link_mbps != null) {
    titleParts.push(`${host.starlink_link_mbps} Mbps link`);
  }
  const title = titleParts.length
    ? ` title="${titleParts.join(" · ").replaceAll('"', "&quot;")}"`
    : "";

  return `<span class="starlink-signal ${qualityClass}"${title}><strong>${escapeHtml(label)}</strong></span>`;
}

function downloadTextFile(filename, content, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

function exportHostsCsv() {
  const hosts = getVisibleHosts();
  const headers = [
    "ip",
    "mac",
    "vendor",
    "hostname",
    "infra_role_labels",
    "device_role",
    "connection_label",
    "connection",
    "starlink_band",
    "starlink_signal_dbm",
    "starlink_snr",
    "starlink_name",
    "os",
    "scan_change",
  ];
  const rows = [headers.join(",")];
  for (const host of hosts) {
    rows.push(
      headers
        .map((key) => {
          const value = host[key] ?? "";
          const text = String(value);
          if (/[",\n]/.test(text)) {
            return `"${text.replaceAll('"', '""')}"`;
          }
          return text;
        })
        .join(",")
    );
  }
  const stamp = new Date().toISOString().slice(0, 19).replaceAll(":", "-").replace("T", "-");
  downloadTextFile(`lan-scan-${stamp}.csv`, rows.join("\n"), "text/csv;charset=utf-8");
}

function exportHostsJson() {
  const hosts = getVisibleHosts();
  const payload = {
    exported_at: new Date().toISOString(),
    filter: hostFilterQuery.trim() || null,
    host_count: hosts.length,
    scan_summary: lastScanSummary,
    hosts,
  };
  const stamp = new Date().toISOString().slice(0, 19).replaceAll(":", "-").replace("T", "-");
  downloadTextFile(
    `lan-scan-${stamp}.json`,
    JSON.stringify(payload, null, 2),
    "application/json;charset=utf-8"
  );
}

async function loadNetworkInfo() {
  const response = await fetch("/api/network");
  if (!response.ok) {
    networkInfo.textContent = "Network detection failed";
    return;
  }

  const data = await response.json();
  networkMeta = data;
  let badge = `${data.network} via ${data.interface} (${data.address})`;
  if (data.starlink?.available) {
    badge += ` · Starlink ${data.starlink.client_count} clients`;
  } else if (data.starlink?.error) {
    badge += " · connections: guess mode";
  }
  networkInfo.textContent = badge;

  if (data.starlink?.available) {
    renderStarlinkPanel(data.starlink);
  } else {
    showStarlinkUnavailable(data.starlink);
  }

  if (data.needs_setup) {
    setupNotice.classList.remove("hidden");
    setupMessage.textContent = data.message;
    setupCommand.textContent = data.setup_command;
    starlinkPanel.classList.add("hidden");
  } else if (data.starlink && !data.starlink.available && data.starlink.error) {
    setupNotice.classList.remove("hidden");
    setupMessage.textContent = `Starlink connection data unavailable: ${data.starlink.error}. Run “Network Scanner — Starlink Setup” on your desktop, then restart the scanner and rescan.`;
    setupCommand.textContent = "~/Projects/lan-network-scanner/scripts/install-starlink-support.sh";
    starlinkPanel.classList.add("hidden");
  } else {
    setupNotice.classList.add("hidden");
  }
  renderTopology();
}

function setStatus(element, message, className = "") {
  element.textContent = message;
  element.className = `status ${className}`.trim();
}

function clearHostsTable(options = {}) {
  const { keepFilter = false, keepSelection = false } = options;
  discoveredHosts = [];
  hostsBody.innerHTML = "";
  hostCount = 0;
  if (!keepSelection) {
    selectedHostIp = null;
  }
  lastScanSummary = null;
  if (!keepFilter) {
    hostFilterQuery = "";
    if (hostsFilterInput) {
      hostsFilterInput.value = "";
    }
  }
  renderDiscoverySummary(null);
  updateHostsToolbar();
  renderTopology();
}

function compareIpAddress(left, right) {
  const toParts = (ip) => String(ip || "").split(".").map((part) => parseInt(part, 10) || 0);
  const leftParts = toParts(left);
  const rightParts = toParts(right);
  for (let index = 0; index < 4; index += 1) {
    if (leftParts[index] !== rightParts[index]) {
      return leftParts[index] - rightParts[index];
    }
  }
  return 0;
}

function compareText(left, right) {
  const leftValue = (left || "").toLowerCase();
  const rightValue = (right || "").toLowerCase();
  if (!leftValue && rightValue) {
    return 1;
  }
  if (leftValue && !rightValue) {
    return -1;
  }
  return leftValue.localeCompare(rightValue, undefined, { sensitivity: "base", numeric: true });
}

function compareHosts(left, right, column) {
  switch (column) {
    case "ip":
      return compareIpAddress(left.ip, right.ip);
    case "mac":
      return compareText(left.mac || "", right.mac || "");
    case "vendor":
      return compareText(left.vendor || "", right.vendor || "");
    case "hostname":
      return compareText(left.hostname || "", right.hostname || "");
    case "infra":
      return compareText(left.infra_role_labels || "", right.infra_role_labels || "");
    case "services":
      return compareText(left.device_role || "", right.device_role || "");
    case "connection": {
      const leftRank = CONNECTION_SORT_ORDER[left.connection] ?? 99;
      const rightRank = CONNECTION_SORT_ORDER[right.connection] ?? 99;
      if (leftRank !== rightRank) {
        return leftRank - rightRank;
      }
      return compareText(left.connection_label || "", right.connection_label || "");
    }
    case "starlink": {
      const leftScore = left.starlink_snr ?? left.starlink_signal_dbm ?? -9999;
      const rightScore = right.starlink_snr ?? right.starlink_signal_dbm ?? -9999;
      if (left.connection_source !== "starlink" && right.connection_source === "starlink") {
        return 1;
      }
      if (left.connection_source === "starlink" && right.connection_source !== "starlink") {
        return -1;
      }
      if (leftScore !== rightScore) {
        return leftScore - rightScore;
      }
      return compareText(left.starlink_band || "", right.starlink_band || "");
    }
    case "os":
      return compareText(left.os || "", right.os || "");
    default:
      return compareIpAddress(left.ip, right.ip);
  }
}

function updateHostSortHeaders() {
  document.querySelectorAll("th.sortable[data-sort]").forEach((header) => {
    const column = header.dataset.sort;
    header.classList.remove("sorted-asc", "sorted-desc");
    if (column === hostSort.column) {
      header.classList.add(hostSort.direction === "asc" ? "sorted-asc" : "sorted-desc");
      header.setAttribute("aria-sort", hostSort.direction === "asc" ? "ascending" : "descending");
    } else {
      header.setAttribute("aria-sort", "none");
    }
  });
}

function renderHostsTable() {
  const sortedHosts = getVisibleHosts();

  hostsBody.innerHTML = "";
  hostCount = sortedHosts.length;
  updateHostsToolbar();

  if (hostCount === 0) {
    const message = discoveredHosts.length
      ? "No hosts match your filter."
      : "No hosts discovered yet.";
    hostsBody.innerHTML = `
      <tr class="empty-row">
        <td colspan="9">${message}</td>
      </tr>
    `;
    return;
  }

  sortedHosts.forEach((host) => {
    hostsBody.appendChild(createHostRow(host));
  });
  renderTopology();
}

function setHostSort(column) {
  if (hostSort.column === column) {
    hostSort.direction = hostSort.direction === "asc" ? "desc" : "asc";
  } else {
    hostSort.column = column;
    hostSort.direction = column === "ip" ? "asc" : "asc";
  }
  saveUiPrefs();
  updateHostSortHeaders();
  if (discoveredHosts.length > 0) {
    renderHostsTable();
  }
}

function updateRestoreButton() {
  if (!restoreLastScanBtn) {
    return;
  }
  const canRestore = lastScanAvailable && discoveredHosts.length === 0;
  restoreLastScanBtn.classList.toggle("hidden", !canRestore);
  restoreLastScanBtn.disabled = !canRestore;
}

async function checkLastScanAvailable() {
  try {
    const response = await fetch("/api/scan/last");
    if (!response.ok) {
      lastScanAvailable = false;
      updateRestoreButton();
      return;
    }
    const data = await response.json();
    lastScanAvailable = Boolean(data.available && data.hosts?.length);
    updateRestoreButton();
  } catch {
    lastScanAvailable = false;
    updateRestoreButton();
  }
}

function restoreHostsFromPayload(hosts, summary) {
  discoveredHosts = hosts.map((host) => ({ ...host }));
  lastScanSummary = summary || null;
  hostFilterQuery = "";
  if (hostsFilterInput) {
    hostsFilterInput.value = "";
  }
  renderHostsTable();
  renderDiscoverySummary(lastScanSummary);
  updateHostsToolbar();
  if (selectedHostIp && !discoveredHosts.some((host) => host.ip === selectedHostIp)) {
    selectedHostIp = null;
  }
}

async function restoreLastScan() {
  if (!lastScanAvailable || discoveredHosts.length > 0) {
    return;
  }

  restoreLastScanBtn.disabled = true;
  try {
    const response = await fetch("/api/scan/last");
    if (!response.ok) {
      throw new Error("Could not load last scan");
    }
    const data = await response.json();
    if (!data.available || !data.hosts?.length) {
      lastScanAvailable = false;
      updateRestoreButton();
      setStatus(discoveryStatus, "No saved scan to restore.", "error");
      return;
    }

    restoreHostsFromPayload(data.hosts, data.summary);
    const when = data.scanned_at ? ` from ${data.scanned_at}` : "";
    setStatus(
      discoveryStatus,
      `Restored ${data.hosts.length} host${data.hosts.length === 1 ? "" : "s"}${when}. Run Scan Network for fresh results.`,
      "done",
    );
  } catch {
    setStatus(discoveryStatus, "Could not restore last scan.", "error");
  } finally {
    updateRestoreButton();
  }
}

function cancelDiscoveryScan(message = "Discovery scan stopped.") {
  if (discoverySource) {
    discoverySource.close();
    discoverySource = null;
  }
  scanNetworkBtn.disabled = false;
  stopDiscoveryBtn.classList.add("hidden");
  setStatus(discoveryStatus, message, discoveredHosts.length ? "done" : "");
  scheduleAutoRescan();
}

function cancelPortScan(message = "Port scan stopped.") {
  if (portSource) {
    portSource.close();
    portSource = null;
  }
  scanPortsBtn.disabled = false;
  stopPortScanBtn.classList.add("hidden");
  const host = targetHostInput.value.trim();
  setStatus(
    portStatus,
    openPortCount
      ? `${message} ${openPortCount} open port${openPortCount === 1 ? "" : "s"} found on ${host}.`
      : message,
    openPortCount ? "done" : "",
  );
}

function clearPortsTable() {
  resetPortMonitor();
  portsBody.innerHTML = "";
  openPortCount = 0;
}

function formatServices(host) {
  if (!host.device_role) {
    return '<span class="service-hint missing">—</span>';
  }
  const title = host.mdns_services?.length
    ? host.mdns_services
        .map((service) => {
          const source = service.source || service.name || "mdns";
          return `${service.hint} (${source})`;
        })
        .join(" · ")
        .replaceAll('"', "&quot;")
    : "";
  return `<button type="button" class="service-hint service-hint-button" data-host-ip="${escapeHtml(host.ip)}" title="${title}">${escapeHtml(host.device_role)}</button>`;
}

async function refreshServicesPanel() {
  try {
    const [graphResponse, certResponse] = await Promise.all([
      fetch("/api/services/graph"),
      fetch("/api/certificates"),
    ]);

    if (graphResponse.ok) {
      const graph = await graphResponse.json();
      const hosts = graph.hosts || [];
      const withServices = hosts.filter((item) => item.services?.length);
      const withApps = hosts.filter((item) => item.applications?.length);
      renderServicesHostsTable(hosts);
      if (servicesSummary) {
        servicesSummary.innerHTML = `
          <span><strong>${graph.host_count || 0}</strong> hosts in graph</span>
          <span><strong>${withServices.length}</strong> with discovered services</span>
          <span><strong>${withApps.length}</strong> with scanned applications</span>
        `;
      }
      if (servicesStatus) {
        if (withApps.length) {
          setStatus(
            servicesStatus,
            `${withApps.length} host${withApps.length === 1 ? "" : "s"} with application-layer data. Click a row below or Services in the discovery table for details.`,
            "done",
          );
        } else if (withServices.length) {
          setStatus(
            servicesStatus,
            `${withServices.length} host${withServices.length === 1 ? "" : "s"} with discovered services. Port-scan hosts for HTTP titles, TLS certificates, and banners.`,
            "done",
          );
        } else if (graph.host_count > 0) {
          setStatus(
            servicesStatus,
            "Hosts found but no services detected yet. Run Scan Network again or port-scan individual hosts.",
            "",
          );
        } else {
          setStatus(
            servicesStatus,
            "Run Scan Network first, then port-scan hosts to collect application data.",
            "",
          );
        }
      }
    } else if (servicesStatus) {
      setStatus(servicesStatus, "Could not load service graph.", "error");
      renderServicesHostsTable([]);
    }

    if (certResponse.ok) {
      const data = await certResponse.json();
      renderCertificatesTable(data.certificates || []);
    } else if (certificatesBody) {
      renderCertificatesTable([]);
    }
  } catch {
    if (servicesStatus) {
      setStatus(servicesStatus, "Could not load service graph.", "error");
    }
    renderServicesHostsTable([]);
  }
}

function formatApplicationSummary(app) {
  const proto = String(app.protocol || "tcp").toUpperCase();
  const port = app.port ?? "—";
  const detail =
    app.probe?.summary || app.banner || app.service || app.state || "";
  return detail ? `${proto} ${port}: ${detail}` : `${proto} ${port}`;
}

function renderServicesHostsTable(hosts) {
  if (!servicesHostsBody) {
    return;
  }

  const enriched = (hosts || []).filter(
    (host) => host.services?.length || host.applications?.length,
  );
  enriched.sort((left, right) => String(left.host).localeCompare(String(right.host)));

  if (!enriched.length) {
    servicesHostsBody.innerHTML = `
      <tr class="empty-row">
        <td colspan="3">No services discovered yet. Run Scan Network, then port-scan hosts for application details.</td>
      </tr>
    `;
    return;
  }

  servicesHostsBody.innerHTML = enriched
    .map((host) => {
      const serviceLabels = (host.services || [])
        .map((service) => service.label)
        .filter(Boolean)
        .join(" · ");
      const applications = (host.applications || [])
        .map((app) => formatApplicationSummary(app))
        .join(" · ");
      return `
        <tr class="services-host-row" data-host-ip="${escapeHtml(host.host)}" tabindex="0" role="button" title="Show full service graph">
          <td class="mono">${escapeHtml(host.host)}</td>
          <td>${escapeHtml(host.role || serviceLabels || "—")}</td>
          <td class="services-apps-cell">${escapeHtml(applications || "—")}</td>
        </tr>
      `;
    })
    .join("");

  servicesHostsBody.querySelectorAll(".services-host-row").forEach((row) => {
    const openGraph = () => showHostServiceGraph(row.dataset.hostIp);
    row.addEventListener("click", openGraph);
    row.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        openGraph();
      }
    });
  });
}

function renderCertificatesTable(certificates) {
  if (!certificatesBody) {
    return;
  }

  if (!certificates.length) {
    certificatesBody.innerHTML = `
      <tr class="empty-row">
        <td colspan="6">No TLS certificates collected yet. Scan HTTPS ports on a host.</td>
      </tr>
    `;
    return;
  }

  certificatesBody.innerHTML = certificates
    .map((cert) => {
      const match =
        cert.hostname_match === true
          ? "Yes"
          : cert.hostname_match === false
            ? "Mismatch"
            : "—";
      const expired = cert.expired ? '<span class="cert-expired">Expired</span>' : "";
      return `
        <tr>
          <td class="mono">${escapeHtml(cert.host)}</td>
          <td class="mono">${escapeHtml(cert.port)}</td>
          <td>${escapeHtml(cert.subject || "—")}</td>
          <td>${escapeHtml(cert.issuer || "—")}</td>
          <td>${escapeHtml(cert.not_after || "—")} ${expired}</td>
          <td>${match}</td>
        </tr>
      `;
    })
    .join("");
}

function openServiceModalError(hostIp, message) {
  if (!serviceModal) {
    return;
  }
  serviceModalTitle.textContent = `Services on ${hostIp}`;
  serviceModalRole.textContent = message;
  serviceModalContent.innerHTML =
    "<p class='muted'>Try running Scan Network or port-scanning this host, then open Services again.</p>";
  serviceModal.classList.remove("hidden");
  serviceModal.setAttribute("aria-hidden", "false");
}

async function showHostServiceGraph(hostIp) {
  if (!serviceModal) {
    return;
  }
  try {
    const response = await fetch(`/api/hosts/${encodeURIComponent(hostIp)}/service-graph`);
    if (!response.ok) {
      let detail = `Could not load services (${response.status}).`;
      try {
        const data = await response.json();
        if (data.detail) {
          detail = String(data.detail);
        }
      } catch {
        // Use default message.
      }
      openServiceModalError(hostIp, detail);
      return;
    }
    const graph = await response.json();
    serviceModalTitle.textContent = `Services on ${hostIp}`;
    serviceModalRole.textContent = graph.role || "No service summary yet.";
    const serviceList = (graph.services || [])
      .map(
        (service) =>
          `<li><strong>${escapeHtml(service.label)}</strong> <span class="muted">(${escapeHtml(service.source)})</span></li>`,
      )
      .join("");
    const appList = (graph.applications || [])
      .map((app) => {
        const proto = (app.protocol || "tcp").toUpperCase();
        const detail = app.banner || app.probe?.summary || app.service || app.state || "";
        return `<li><span class="mono">${proto} ${escapeHtml(app.port)}</span> — ${escapeHtml(detail || "open")}</li>`;
      })
      .join("");
    serviceModalContent.innerHTML = `
      <div class="service-modal-section">
        <span class="modal-label">Discovered services</span>
        <ul class="service-modal-list">${serviceList || "<li class='muted'>None yet — run Scan Network or port-scan this host.</li>"}</ul>
      </div>
      <div class="service-modal-section">
        <span class="modal-label">Applications (from port scans)</span>
        <ul class="service-modal-list">${appList || "<li class='muted'>Port-scan this host for HTTP titles, TLS certs, and UDP services.</li>"}</ul>
      </div>
    `;
    serviceModal.classList.remove("hidden");
    serviceModal.setAttribute("aria-hidden", "false");
  } catch {
    openServiceModalError(hostIp, "Could not load service graph.");
  }
}

function closeServiceModal() {
  if (!serviceModal) {
    return;
  }
  serviceModal.classList.add("hidden");
  serviceModal.setAttribute("aria-hidden", "true");
}

function applyServiceDataToHost(hostIp, data) {
  const host = discoveredHosts.find((item) => item.ip === hostIp);
  if (!host) {
    return false;
  }
  host.mdns_services = data?.services || data?.service_hints || [];
  host.device_role = data?.device_role || null;
  renderHostsTable();
  return true;
}

async function refreshHostServices(hostIp) {
  const trimmed = hostIp.trim();
  if (!trimmed) {
    return;
  }
  try {
    const response = await fetch(`/api/hosts/${encodeURIComponent(trimmed)}/services`);
    if (!response.ok) {
      return;
    }
    const data = await response.json();
    applyServiceDataToHost(trimmed, data);
  } catch {
    // Host services are optional UI enrichment.
  }
}

function formatConnection(host) {
  const label = host.connection_label || "Unknown";
  const parts = [];
  if (host.connection_detail) {
    parts.push(host.connection_detail);
  }
  if (host.connection_source === "guess") {
    parts.push("estimated from vendor");
  } else if (host.connection_source === "starlink") {
    parts.push("from Starlink router");
  } else if (host.connection_source === "local" && host.is_local) {
    parts.push("this machine's active interface");
  }
  const title = parts.length ? ` title="${parts.join(" · ").replaceAll('"', "&quot;")}"` : "";
  const cssClass = host.connection ? ` connection-${host.connection}` : "";
  return `<span class="connection-badge${cssClass}"${title}>${label}</span>`;
}

function guessGatewayIp(networkCidr) {
  if (!networkCidr) {
    return null;
  }
  const base = String(networkCidr).split("/")[0];
  const parts = base.split(".").map((part) => parseInt(part, 10));
  if (parts.length !== 4 || parts.some((part) => Number.isNaN(part))) {
    return null;
  }
  parts[3] = 1;
  return parts.join(".");
}

function findGatewayHost(hosts, gatewayIp) {
  const candidates = [gatewayIp, "192.168.1.1", "192.168.0.1", "10.0.0.1"].filter(Boolean);
  for (const ip of candidates) {
    const host = hosts.find((item) => item.ip === ip);
    if (host) {
      return host;
    }
  }
  return (
    hosts.find((host) =>
      /router|gateway|starlink|netgear|tp-link|tplink|asus|synology|unifi|eero|linksys/i.test(
        String(host.vendor || ""),
      ),
    ) || null
  );
}

function topologyNodeLabel(host) {
  const name = host.hostname && host.hostname !== "—" ? host.hostname : host.ip;
  const sub =
    host.hostname && host.hostname !== "—"
      ? host.ip
      : host.vendor && host.vendor !== "—"
        ? host.vendor
        : "";
  return { name, sub };
}

function renderTopologyNode(host, role) {
  const { name, sub } = topologyNodeLabel(host);
  const classes = [
    "topology-node",
    `topology-node-${role}`,
    host.ip === selectedHostIp ? "selected" : "",
    host.is_local ? "local" : "",
    host.scan_change === "new" ? "novel" : "",
  ]
    .filter(Boolean)
    .join(" ");

  return `
    <button type="button" class="${classes}" data-host-ip="${escapeHtml(host.ip)}" title="${escapeHtml(host.ip)}">
      <span class="topology-node-name">${escapeHtml(name)}</span>
      ${sub ? `<span class="topology-node-sub">${escapeHtml(sub)}</span>` : ""}
      ${host.scan_change === "new" ? '<span class="topology-node-badge">New</span>' : ""}
    </button>
  `;
}

function renderGatewayNode(gatewayHost, gatewayIp, label) {
  if (gatewayHost) {
    return renderTopologyNode(gatewayHost, "gateway");
  }
  return `
    <div class="topology-node topology-node-gateway topology-node-ghost">
      <span class="topology-node-name">${escapeHtml(label)}</span>
      <span class="topology-node-sub">${escapeHtml(gatewayIp || "Not seen in scan")}</span>
    </div>
  `;
}

function renderTopologyBranch(title, kind, hosts) {
  if (!hosts.length) {
    return "";
  }
  const nodes = hosts.map((host) => renderTopologyNode(host, kind)).join("");
  return `
    <div class="topology-branch topology-branch-${kind}">
      <div class="topology-branch-head">${escapeHtml(title)} · ${hosts.length}</div>
      <div class="topology-branch-nodes">${nodes}</div>
    </div>
  `;
}

function renderTopology() {
  if (!topologyPanel || !topologyView) {
    return;
  }

  if (!discoveredHosts.length) {
    topologyPanel.classList.add("hidden");
    topologyView.innerHTML = "";
    return;
  }

  topologyPanel.classList.remove("hidden");
  if (topologySubtitle) {
    topologySubtitle.textContent = networkMeta?.network || "Local network";
  }

  const gatewayIp = guessGatewayIp(networkMeta?.network);
  const gatewayHost = findGatewayHost(discoveredHosts, gatewayIp);
  const localHost = discoveredHosts.find((host) => host.is_local);
  const clients = discoveredHosts.filter((host) => {
    if (host.is_local) {
      return false;
    }
    if (gatewayHost && host.ip === gatewayHost.ip) {
      return false;
    }
    if (!gatewayHost && gatewayIp && host.ip === gatewayIp) {
      return false;
    }
    return true;
  });

  const wifiHosts = clients.filter((host) => host.connection === "wifi");
  const ethernetHosts = clients.filter((host) => host.connection === "ethernet");
  const unknownHosts = clients.filter(
    (host) => host.connection !== "wifi" && host.connection !== "ethernet",
  );

  const gatewayLabel = lastStarlinkSummary?.available ? "Starlink router" : "Gateway";
  const centerBranch = localHost
    ? `
      <div class="topology-branch topology-branch-center">
        <div class="topology-branch-head">This machine</div>
        <div class="topology-branch-nodes">${renderTopologyNode(localHost, "local")}</div>
      </div>
    `
    : "";

  topologyView.innerHTML = `
    <div class="topology-layout">
      <div class="topology-hub">
        ${renderGatewayNode(gatewayHost, gatewayIp, gatewayLabel)}
      </div>
      <div class="topology-spine" aria-hidden="true"></div>
      <div class="topology-branches">
        ${renderTopologyBranch("Wi-Fi", "wifi", wifiHosts)}
        ${centerBranch}
        ${renderTopologyBranch("Ethernet", "ethernet", ethernetHosts)}
        ${renderTopologyBranch("Unknown", "unknown", unknownHosts)}
      </div>
    </div>
  `;

  topologyView.querySelectorAll(".topology-node[data-host-ip]").forEach((button) => {
    button.addEventListener("click", () => {
      setSelectedHost(button.dataset.hostIp);
    });
  });
}

function scrollTopologyToSelectedHost() {
  if (!topologyView || !selectedHostIp) {
    return;
  }

  requestAnimationFrame(() => {
    const node = topologyView.querySelector(
      `.topology-node.selected[data-host-ip="${selectedHostIp}"]`,
    );
    if (!node) {
      return;
    }

    const branch = node.closest(".topology-branch-nodes");
    if (branch && branch.scrollHeight > branch.clientHeight + 1) {
      const top = node.offsetTop - (branch.clientHeight - node.offsetHeight) / 2;
      branch.scrollTo({ top: Math.max(0, top), behavior: "smooth" });
    }

    node.scrollIntoView({ behavior: "smooth", block: "center", inline: "center" });
  });
}

function setSelectedHost(ip, options = {}) {
  const { scroll = false } = options;
  const selectionChanged = selectedHostIp !== ip;
  const scrollTopology = options.scrollTopology ?? !scroll;
  selectedHostIp = ip;
  hostsBody.querySelectorAll("tr[data-host-ip]").forEach((row) => {
    row.classList.toggle("selected-host", row.dataset.hostIp === ip);
  });
  targetHostInput.value = ip;
  refreshPortProfileUi(ip, true);
  if (scroll) {
    scrollToPortScannerPanel();
  }
  renderTopology();
  if (scrollTopology && selectionChanged) {
    scrollTopologyToSelectedHost();
  }
}

function createHostRow(host) {
  const row = document.createElement("tr");
  row.dataset.hostIp = host.ip;
  if (host.is_local) {
    row.classList.add("local-host");
  }
  if (host.ip === selectedHostIp) {
    row.classList.add("selected-host");
  }

  if (host.infra_roles?.length) {
    row.classList.add("infra-host");
  }

  const hostname = host.hostname || "—";
  const infraRoles = formatInfraRoles(host);
  const services = formatServices(host);
  const mac = host.mac || "—";
  const vendor = host.vendor || "—";
  const osName = host.os || "—";
  const osTitle = host.os_detail ? ` title="${host.os_detail.replaceAll('"', "&quot;")}"` : "";
  const connection = formatConnection(host);
  const starlinkSignal = formatStarlinkSignal(host);
  const localBadge = host.is_local ? '<span class="badge">this machine</span>' : "";
  const newBadge = host.scan_change === "new" ? '<span class="badge-new">New</span>' : "";
  const methodBadge = host.method
    ? `<span class="badge method">${host.method}</span>`
    : "";

  row.innerHTML = `
    <td class="copyable-host-ip">${host.ip}${localBadge}${newBadge}</td>
    <td class="mono col-mac copyable-host-mac">${mac}</td>
    <td class="col-vendor">${vendor}${methodBadge}</td>
    <td class="col-hostname">${hostname}</td>
    <td class="col-infra">${infraRoles}</td>
    <td>${services}</td>
    <td>${connection}</td>
    <td>${starlinkSignal}</td>
    <td class="col-os"${osTitle}>${osName}</td>
    <td><button type="button" class="secondary scan-host-btn" data-host="${host.ip}">Scan ports</button></td>
  `;

  attachCopyableCell(row.querySelector(".copyable-host-ip"), host.ip, "IP");
  attachCopyableCell(row.querySelector(".copyable-host-mac"), host.mac, "MAC");

  row.addEventListener("click", (event) => {
    if (event.target.closest(".scan-host-btn, .copyable-cell")) {
      return;
    }
    setSelectedHost(host.ip);
  });

  row.addEventListener("dblclick", (event) => {
    if (event.target.closest(".copyable-cell")) {
      return;
    }
    setSelectedHost(host.ip, { scroll: true });
    startPortScan(host.ip, getSelectedPorts());
  });

  row.querySelector(".scan-host-btn").addEventListener("click", (event) => {
    event.stopPropagation();
    setSelectedHost(host.ip, { scroll: true });
    startPortScan(host.ip, getSelectedPorts());
  });

  const serviceButton = row.querySelector(".service-hint-button");
  if (serviceButton) {
    serviceButton.addEventListener("click", (event) => {
      event.stopPropagation();
      setSelectedHost(host.ip);
      showHostServiceGraph(host.ip);
    });
  }

  return row;
}

function addHostRow(host) {
  discoveredHosts.push(host);
  renderHostsTable();
}

function formatPortBanner(banner) {
  if (!banner) {
    return '<span class="banner-missing">—</span>';
  }
  const text = String(banner);
  const display = text.length > 72 ? `${text.slice(0, 69)}…` : text;
  return `<span class="port-banner mono" title="${escapeHtml(text)}">${escapeHtml(display)}</span>`;
}

function addPortRow(result) {
  if (openPortCount === 0) {
    portsBody.innerHTML = "";
  }

  openPortCount += 1;
  const row = document.createElement("tr");
  row.classList.add("port-row");
  row.dataset.port = String(result.port);
  const protocol = result.protocol === "udp" ? "UDP" : "TCP";
  const monitorCell =
    result.protocol === "udp"
      ? '<span class="muted">—</span>'
      : '<button type="button" class="secondary monitor-port-btn">Monitor</button>';
  row.innerHTML = `
    <td class="port-cell mono">${protocol} ${result.port}</td>
    <td>${result.service}</td>
    <td>${formatPortBanner(result.banner)}</td>
    <td>${result.state}</td>
    <td>${monitorCell}</td>
  `;

  row.addEventListener("dblclick", () => showPortInfo(result));
  const monitorBtn = row.querySelector(".monitor-port-btn");
  if (monitorBtn) {
    monitorBtn.addEventListener("click", (event) => {
      event.stopPropagation();
      startPortMonitor(result);
    });
  }
  portsBody.appendChild(row);
}

const WEB_PORTS = new Set([80, 443, 8000, 8080, 8443, 8888, 9000]);

function buildWebUrl(host, port) {
  const scheme = port === 443 || port === 8443 ? "https" : "http";
  if ((scheme === "http" && port === 80) || (scheme === "https" && port === 443)) {
    return `${scheme}://${host}`;
  }
  return `${scheme}://${host}:${port}`;
}

function getConnectOptions(host, port, service) {
  if (!host) {
    return [];
  }

  const options = [];
  const serviceName = (service || "").toLowerCase();

  if (port === 22 || serviceName.includes("ssh")) {
    options.push({
      type: "copy",
      label: "Copy SSH command",
      value: port === 22 ? `ssh ${host}` : `ssh -p ${port} ${host}`,
    });
    options.push({
      type: "ssh",
      label: "Open SSH client",
      host,
      port,
    });
  }

  if (WEB_PORTS.has(port) || serviceName.includes("http")) {
    const url = buildWebUrl(host, port);
    options.push({
      type: "open",
      label: "Open in browser",
      url,
    });
    options.push({
      type: "copy",
      label: "Copy URL",
      value: url,
    });
  }

  if (port === 3389 || serviceName.includes("rdp")) {
    options.push({
      type: "copy",
      label: "Copy RDP command",
      value: `xfreerdp /v:${host}`,
    });
  }

  if (port === 5900 || serviceName.includes("vnc")) {
    const url = `vnc://${host}:${port}`;
    options.push({
      type: "open",
      label: "Open VNC client",
      url,
    });
  }

  if (port === 23 || serviceName.includes("telnet")) {
    options.push({
      type: "copy",
      label: "Copy telnet command",
      value: `telnet ${host} ${port}`,
    });
  }

  if (port === 21 || serviceName.includes("ftp")) {
    options.push({
      type: "copy",
      label: "Copy FTP command",
      value: `ftp ${host}`,
    });
  }

  return options;
}

async function copyConnectValue(value, button) {
  try {
    await navigator.clipboard.writeText(value);
    const original = button.textContent;
    button.textContent = "Copied!";
    setTimeout(() => {
      button.textContent = original;
    }, 1500);
  } catch {
    window.prompt("Copy this command:", value);
  }
}

async function launchSshClient(host, port, button) {
  const original = button.textContent;
  button.disabled = true;
  button.textContent = "Opening...";

  try {
    const params = new URLSearchParams({ host, port: String(port) });
    const response = await fetch(`/api/connect/ssh?${params.toString()}`, {
      method: "POST",
    });
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.detail || "Could not open SSH client");
    }

    portModalConnectNote.textContent = `Launched ${data.client}: ${data.command}`;
  } catch (error) {
    portModalConnectNote.textContent = error.message || "Could not open SSH client.";
  } finally {
    button.disabled = false;
    button.textContent = original;
  }
}

function renderConnectOptions(host, port, service) {
  const options = getConnectOptions(host, port, service);
  portModalConnectActions.innerHTML = "";

  if (!options.length) {
    portModalConnect.classList.add("hidden");
    return;
  }

  portModalConnect.classList.remove("hidden");
  portModalConnectNote.textContent =
    "Open SSH launches a terminal on this PC. Copy command if you prefer to connect manually.";

  options.forEach((option) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = option.type === "open" || option.type === "ssh" ? "primary" : "secondary";
    button.textContent = option.label;

    if (option.type === "open") {
      button.addEventListener("click", () => {
        window.open(option.url, "_blank", "noopener,noreferrer");
      });
    } else if (option.type === "ssh") {
      button.addEventListener("click", () => {
        launchSshClient(option.host, option.port, button);
      });
    } else {
      button.addEventListener("click", () => {
        copyConnectValue(option.value, button);
      });
    }

    portModalConnectActions.appendChild(button);
  });
}

function showPortInfo(result) {
  const host = targetHostInput.value.trim();
  const protocol = result.protocol === "udp" ? "UDP" : "TCP";
  portModalTitle.textContent = `${protocol} ${result.port}`;
  portModalService.textContent = result.service && result.service !== "unknown"
    ? result.service
    : "Unknown service";
  portModalDescription.textContent = result.description || "No description available for this port.";
  portModalUse.textContent = result.common_use || "Varies by installed software and configuration.";
  portModalRisk.textContent = result.risk || "Review the service bound to this port before exposing it.";
  if (result.banner) {
    portModalBannerWrap.classList.remove("hidden");
    portModalBanner.textContent = result.banner;
  } else {
    portModalBannerWrap.classList.add("hidden");
    portModalBanner.textContent = "";
  }

  const cert = result.certificate || result.probe;
  if (portModalCertWrap && cert?.protocol === "tls" && cert.subject) {
    portModalCertWrap.classList.remove("hidden");
    portModalCertSubject.textContent = cert.subject;
    const meta = [
      cert.issuer ? `Issuer: ${cert.issuer}` : "",
      cert.not_after ? `Expires: ${cert.not_after}` : "",
      cert.expired ? "Status: expired" : "",
      cert.hostname_match === false ? "Hostname mismatch" : "",
      cert.san?.length ? `SAN: ${cert.san.join(", ")}` : "",
    ].filter(Boolean);
    portModalCertMeta.textContent = meta.join(" · ");
  } else if (portModalCertWrap) {
    portModalCertWrap.classList.add("hidden");
    if (portModalCertSubject) {
      portModalCertSubject.textContent = "";
    }
    if (portModalCertMeta) {
      portModalCertMeta.textContent = "";
    }
  }

  renderConnectOptions(host, result.port, result.service);
  portModal.classList.remove("hidden");
  portModal.setAttribute("aria-hidden", "false");
}

function setActiveMonitorRow(port) {
  portsBody.querySelectorAll(".port-row.monitoring").forEach((row) => {
    row.classList.remove("monitoring");
  });

  activeMonitorPort = port;
  const activeRow = portsBody.querySelector(`.port-row[data-port="${port}"]`);
  if (activeRow) {
    activeRow.classList.add("monitoring");
  }
}

function resetPortMonitor() {
  stopPortMonitor(false);
  portMonitorPanel.classList.add("hidden");
  portMonitorStats.innerHTML = "";
  portMonitorLog.innerHTML = "";
  portMonitorStatus.textContent = "Ready to monitor.";
  portMonitorTitle.textContent = "Port activity";
  portsBody.querySelectorAll(".port-row.monitoring").forEach((row) => {
    row.classList.remove("monitoring");
  });
  activeMonitorPort = null;
}

function stopPortMonitor(updateStatus = true) {
  if (monitorSource) {
    monitorSource.close();
    monitorSource = null;
  }
  if (updateStatus) {
    portMonitorStatus.textContent = "Monitoring stopped.";
  }
  portMonitorStopBtn.classList.add("hidden");
  portsBody.querySelectorAll(".port-row.monitoring").forEach((row) => {
    row.classList.remove("monitoring");
  });
  activeMonitorPort = null;
}

function renderMonitorStats(summary, packets) {
  const packetBlock = packets?.sniffing
    ? `
      <div><strong>${packets.to_port}</strong> packets to port</div>
      <div><strong>${packets.from_port}</strong> packets from port</div>
      <div><strong>${packets.bytes_to + packets.bytes_from}</strong> bytes observed</div>
    `
    : `<div>Packet capture unavailable</div>`;

  portMonitorStats.innerHTML = `
    <div><strong>${summary.open_probes}/${summary.probes}</strong> open probes</div>
    <div><strong>${summary.avg_latency_ms ?? "—"}</strong> ms avg latency</div>
    ${packetBlock}
  `;
}

function appendMonitorLog(message, className = "") {
  const entry = document.createElement("div");
  entry.className = `monitor-entry ${className}`.trim();
  entry.textContent = message;
  portMonitorLog.prepend(entry);
}

function startPortMonitor(result) {
  const host = targetHostInput.value.trim();
  if (!host || !result?.port) {
    return;
  }

  stopPortMonitor(false);
  setActiveMonitorRow(result.port);
  portMonitorPanel.classList.remove("hidden");
  portMonitorStopBtn.classList.remove("hidden");
  portMonitorLog.innerHTML = "";
  portMonitorStats.innerHTML = "";
  portMonitorTitle.textContent = `Activity on ${host}:${result.port}`;
  portMonitorStatus.textContent = `Monitoring ${host}:${result.port}...`;

  const params = new URLSearchParams({
    host,
    port: String(result.port),
    duration: "30",
  });

  monitorSource = consumeEventStream(
    `/api/monitor/port?${params.toString()}`,
    (payload) => {
      if (payload.type === "status") {
        portMonitorStatus.textContent = payload.message;
        return;
      }

      if (payload.type === "probe") {
        const state = payload.open ? "open" : "closed";
        const latency = payload.latency_ms ?? "—";
        let message = `Probe ${payload.index}: ${state} (${latency} ms)`;
        if (payload.banner) {
          message += ` — ${payload.banner}`;
        } else if (payload.error) {
          message += ` — ${payload.error}`;
        }
        appendMonitorLog(message, payload.open ? "open" : "closed");

        if (payload.connections?.length) {
          payload.connections.forEach((connection) => {
            appendMonitorLog(
              `Connection ${connection.state}: ${connection.local} -> ${connection.peer}`,
              "connection",
            );
          });
        }
        return;
      }

      if (payload.type === "summary") {
        renderMonitorStats(payload, payload.packets);
        portMonitorStatus.textContent = "Monitoring complete.";
        portMonitorStopBtn.classList.add("hidden");
        portsBody.querySelectorAll(".port-row.monitoring").forEach((row) => {
          row.classList.remove("monitoring");
        });
        activeMonitorPort = null;
      }
    },
    () => {
      monitorSource = null;
      portMonitorStopBtn.classList.add("hidden");
    },
    () => {
      monitorSource = null;
      portMonitorStatus.textContent = "Monitoring failed.";
      portMonitorStopBtn.classList.add("hidden");
    },
  );
}

function closePortModal() {
  portModal.classList.add("hidden");
  portModal.setAttribute("aria-hidden", "true");
}

portMonitorStopBtn.addEventListener("click", () => stopPortMonitor(true));

portModalClose.addEventListener("click", closePortModal);
portModalBackdrop.addEventListener("click", closePortModal);
if (serviceModalClose) {
  serviceModalClose.addEventListener("click", closeServiceModal);
}
if (serviceModalBackdrop) {
  serviceModalBackdrop.addEventListener("click", closeServiceModal);
}
if (refreshServicesBtn) {
  refreshServicesBtn.addEventListener("click", refreshServicesPanel);
}
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && !portModal.classList.contains("hidden")) {
    closePortModal();
  }
  if (event.key === "Escape" && serviceModal && !serviceModal.classList.contains("hidden")) {
    closeServiceModal();
  }
});

function consumeEventStream(url, onEvent, onDone, onError) {
  const source = new EventSource(url);
  let intentionalClose = false;

  const handle = {
    close() {
      intentionalClose = true;
      source.close();
    },
    source,
  };

  source.onmessage = (event) => {
    const payload = JSON.parse(event.data);
    onEvent(payload);
    if (payload.type === "done") {
      intentionalClose = true;
      source.close();
      onDone();
    }
  };

  source.onerror = () => {
    if (intentionalClose) {
      return;
    }
    source.close();
    onError();
  };

  return handle;
}

function startDiscoveryScan(options = {}) {
  const { auto = false } = options;
  if (discoverySource) {
    discoverySource.close();
  }

  const previousSelection = selectedHostIp;
  clearHostsTable({ keepFilter: auto, keepSelection: auto });
  if (auto && previousSelection) {
    selectedHostIp = previousSelection;
  }

  scanNetworkBtn.disabled = true;
  stopDiscoveryBtn.classList.remove("hidden");
  const statusPrefix = auto
    ? "Auto-refresh: scanning local network..."
    : "Scanning local network for active hosts...";
  setStatus(discoveryStatus, statusPrefix, "scanning");
  updateAutoRescanStatus();

  discoverySource = consumeEventStream(
    "/api/scan/discovery",
    (payload) => {
      if (payload.type === "status") {
        setStatus(discoveryStatus, payload.message, "scanning");
        return;
      }
      if (payload.type === "summary") {
        lastScanSummary = payload;
        renderDiscoverySummary(payload);
        if (payload.starlink) {
          renderStarlinkPanel(payload.starlink);
        }
        renderTopology();
        return;
      }
      if (payload.type === "host") {
        addHostRow(payload.host);
        setStatus(
          discoveryStatus,
          `Found ${hostCount} host${hostCount === 1 ? "" : "s"} so far...`,
          "scanning",
        );
      }
    },
    () => {
      discoverySource = null;
      scanNetworkBtn.disabled = false;
      stopDiscoveryBtn.classList.add("hidden");
      lastScanAvailable = true;
      updateRestoreButton();
      if (selectedHostIp && discoveredHosts.some((host) => host.ip === selectedHostIp)) {
        setSelectedHost(selectedHostIp);
      }
      let message = hostCount
        ? `Discovery complete. Found ${hostCount} active host${hostCount === 1 ? "" : "s"}.`
        : "Discovery complete. No active hosts responded.";
      if (lastScanSummary?.first_scan) {
        message += " Baseline saved for next scan.";
      } else if (lastScanSummary?.new_count > 0) {
        message += ` ${lastScanSummary.new_count} new since last scan.`;
      }
      if (lastScanSummary?.disappeared?.length) {
        message += ` ${lastScanSummary.disappeared.length} no longer seen.`;
      }
      setStatus(discoveryStatus, message, "done");
      notifyNewDevicesIfNeeded();
      scheduleAutoRescan();
      refreshServicesPanel();
    },
    () => {
      discoverySource = null;
      scanNetworkBtn.disabled = false;
      stopDiscoveryBtn.classList.add("hidden");
      setStatus(discoveryStatus, "Discovery scan failed.", "error");
    },
  );
}

function getSelectedPorts() {
  if (targetPortsPreset.value === "custom") {
    return targetPortsCustom.value.trim();
  }
  return targetPortsPreset.value;
}

function resetPortFormToDefault() {
  targetPortsPreset.value = "common";
  targetPortsCustom.value = "";
  targetPortsCustom.classList.add("hidden");
}

function applyPortProfile(portsSpec) {
  const knownPresets = new Set(["common", "1-1024", "all"]);
  if (knownPresets.has(portsSpec)) {
    targetPortsPreset.value = portsSpec;
    targetPortsCustom.classList.add("hidden");
    return;
  }
  targetPortsPreset.value = "custom";
  targetPortsCustom.value = portsSpec;
  targetPortsCustom.classList.remove("hidden");
}

async function refreshPortProfileUi(host, autoApply = false) {
  const trimmedHost = host.trim();
  if (!trimmedHost) {
    currentPortProfile = null;
    portProfileStatus.textContent = "No saved port profile for this host.";
    loadPortProfileBtn.disabled = true;
    savePortProfileBtn.disabled = true;
    clearPortProfileBtn.disabled = true;
    return;
  }

  savePortProfileBtn.disabled = false;
  clearPortProfileBtn.disabled = false;

  try {
    const response = await fetch(`/api/port-profiles/${encodeURIComponent(trimmedHost)}`);
    if (!response.ok) {
      currentPortProfile = null;
      portProfileStatus.textContent = `No saved port profile for ${trimmedHost}.`;
      loadPortProfileBtn.disabled = true;
      resetPortFormToDefault();
      await refreshHostServices(trimmedHost);
      return;
    }
    currentPortProfile = await response.json();
    const label = currentPortProfile.label ? ` (${currentPortProfile.label})` : "";
    portProfileStatus.textContent = `Saved profile${label}: ${currentPortProfile.ports}`;
    loadPortProfileBtn.disabled = false;
    if (autoApply) {
      applyPortProfile(currentPortProfile.ports);
    }
  } catch {
    portProfileStatus.textContent = "Could not load port profile.";
    loadPortProfileBtn.disabled = true;
  }
}

async function clearPortProfile() {
  const host = targetHostInput.value.trim();
  if (!host) {
    setStatus(portStatus, "Enter a host before clearing its profile.", "error");
    return;
  }

  savePortProfileBtn.disabled = true;
  try {
    const response = await fetch(`/api/port-profiles/${encodeURIComponent(host)}`, {
      method: "DELETE",
    });
    if (!response.ok && response.status !== 404) {
      const data = await response.json();
      throw new Error(data.detail || "Could not clear profile");
    }
    currentPortProfile = null;
    portProfileStatus.textContent = `No saved port profile for ${host}.`;
    loadPortProfileBtn.disabled = true;
    resetPortFormToDefault();
    await refreshHostServices(host);
    setStatus(portStatus, `Cleared port profile for ${host}.`, "done");
  } catch (error) {
    setStatus(portStatus, error.message || "Could not clear port profile.", "error");
  } finally {
    savePortProfileBtn.disabled = Boolean(host);
  }
}

async function saveCurrentPortProfile() {
  const host = targetHostInput.value.trim();
  const ports = getSelectedPorts();
  if (!host) {
    setStatus(portStatus, "Enter a host before saving a profile.", "error");
    return;
  }

  if (targetPortsPreset.value === "custom" && !ports) {
    await clearPortProfile();
    return;
  }

  if (!ports) {
    setStatus(portStatus, "Choose ports to save, or switch to Custom and clear the field to remove a profile.", "error");
    return;
  }

  savePortProfileBtn.disabled = true;
  try {
    const response = await fetch(`/api/port-profiles/${encodeURIComponent(host)}`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ports }),
    });
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.detail || "Could not save profile");
    }
    currentPortProfile = data;
    portProfileStatus.textContent = `Saved profile: ${data.ports}`;
    loadPortProfileBtn.disabled = false;
    await refreshHostServices(host);
    setStatus(portStatus, `Saved port profile for ${host}.`, "done");
  } catch (error) {
    setStatus(portStatus, error.message || "Could not save port profile.", "error");
  } finally {
    savePortProfileBtn.disabled = Boolean(host);
  }
}

function updatePortsField() {
  const isCustom = targetPortsPreset.value === "custom";
  targetPortsCustom.classList.toggle("hidden", !isCustom);
  if (isCustom) {
    targetPortsCustom.focus();
  }
}

targetPortsPreset.addEventListener("change", updatePortsField);

function startPortScan(host, ports) {
  if (!host) {
    return;
  }

  const portSpec = ports?.trim() || "common";
  if (targetPortsPreset.value === "custom" && !portSpec) {
    setStatus(portStatus, "Enter custom ports, for example 22,80,443.", "error");
    return;
  }

  if (portSource) {
    portSource.close();
  }

  clearPortsTable();
  scanPortsBtn.disabled = true;
  stopPortScanBtn.classList.remove("hidden");
  const normalizedPorts = portSpec.toLowerCase();
  const scanningAll = normalizedPorts === "all" || normalizedPorts === "full" || normalizedPorts === "1-65535";
  const statusPrefix = scanningAll
    ? `Scanning all 65535 ports on ${host}. This can take several minutes...`
    : `Scanning ${host} (${portSpec})...`;
  setStatus(portStatus, statusPrefix, "scanning");

  const params = new URLSearchParams({ host, ports: portSpec });
  portSource = consumeEventStream(
    `/api/scan/ports?${params.toString()}`,
    (payload) => {
      if (payload.type === "progress") {
        const percent = Math.round((payload.scanned / payload.total) * 100);
        setStatus(
          portStatus,
          `Scanning ${host}... ${payload.scanned}/${payload.total} ports checked (${percent}%).`,
          "scanning",
        );
        return;
      }
      if (payload.type === "port") {
        addPortRow(payload.result);
        setStatus(
          portStatus,
          `Scanning ${host}... ${openPortCount} open port${openPortCount === 1 ? "" : "s"} found.`,
          "scanning",
        );
      }
    },
    () => {
      portSource = null;
      scanPortsBtn.disabled = false;
      stopPortScanBtn.classList.add("hidden");
      refreshHostServices(host);
      setStatus(
        portStatus,
        openPortCount
          ? `Port scan complete. ${openPortCount} open port${openPortCount === 1 ? "" : "s"} on ${host}.`
          : `Port scan complete. No open ports found on ${host}.`,
        "done",
      );
      refreshServicesPanel();
    },
    () => {
      portSource = null;
      scanPortsBtn.disabled = false;
      stopPortScanBtn.classList.add("hidden");
      setStatus(portStatus, "Port scan failed.", "error");
    },
  );
}

scanNetworkBtn.addEventListener("click", () => startDiscoveryScan());
stopDiscoveryBtn.addEventListener("click", () => cancelDiscoveryScan());
restoreLastScanBtn.addEventListener("click", restoreLastScan);
stopPortScanBtn.addEventListener("click", () => cancelPortScan());
themeToggleBtn.addEventListener("click", toggleTheme);

if (autoRescanSelect) {
  autoRescanSelect.addEventListener("change", () => {
    uiPrefs.autoRescanMinutes = Number(autoRescanSelect.value) || 0;
    saveUiPrefs();
    scheduleAutoRescan();
  });
}

if (notifyNewDevicesCheckbox) {
  notifyNewDevicesCheckbox.addEventListener("change", async () => {
    if (notifyNewDevicesCheckbox.checked) {
      await enableDeviceNotifications();
      return;
    }
    uiPrefs.notifyNewDevices = false;
    saveUiPrefs();
    await updateNotifyStatus();
  });
}

document.querySelectorAll("th.sortable[data-sort]").forEach((header) => {
  header.addEventListener("click", () => {
    setHostSort(header.dataset.sort);
  });
});

if (hostsFilterInput) {
  hostsFilterInput.addEventListener("input", () => {
    hostFilterQuery = hostsFilterInput.value;
    renderHostsTable();
  });
}

exportHostsCsvBtn.addEventListener("click", exportHostsCsv);
exportHostsJsonBtn.addEventListener("click", exportHostsJson);

targetHostInput.addEventListener("input", () => {
  const ip = targetHostInput.value.trim();
  refreshPortProfileUi(ip);
  if (ip && discoveredHosts.some((host) => host.ip === ip)) {
    setSelectedHost(ip);
  }
});
targetHostInput.addEventListener("change", () => {
  const ip = targetHostInput.value.trim();
  refreshPortProfileUi(ip, true);
  if (ip && discoveredHosts.some((host) => host.ip === ip)) {
    setSelectedHost(ip);
  }
});
loadPortProfileBtn.addEventListener("click", () => {
  if (currentPortProfile?.ports) {
    applyPortProfile(currentPortProfile.ports);
    setStatus(portStatus, `Loaded saved profile: ${currentPortProfile.ports}`, "done");
  }
});
savePortProfileBtn.addEventListener("click", saveCurrentPortProfile);
clearPortProfileBtn.addEventListener("click", clearPortProfile);

loadUiPrefs();
updateHostSortHeaders();

portScanForm.addEventListener("submit", (event) => {
  event.preventDefault();
  const host = targetHostInput.value.trim();
  if (host && discoveredHosts.some((item) => item.ip === host)) {
    setSelectedHost(host);
  }
  startPortScan(host, getSelectedPorts());
});

loadNetworkInfo();
checkLastScanAvailable();
scheduleAutoRescan();
updateNotifyStatus();
refreshServicesPanel();
