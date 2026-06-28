const hostsBody = document.getElementById("hosts-body");
const portsBody = document.getElementById("ports-body");
const networkInfo = document.getElementById("network-info");
const discoveryStatus = document.getElementById("discovery-status");
const portStatus = document.getElementById("port-status");
const scanNetworkBtn = document.getElementById("scan-network-btn");
const scanPortsBtn = document.getElementById("scan-ports-btn");
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

function hostMatchesFilter(host, query) {
  if (!query) {
    return true;
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

function renderDiscoverySummary(summary) {
  if (!summary) {
    discoverySummary.classList.add("hidden");
    discoverySummary.innerHTML = "";
    return;
  }

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
}

function setStatus(element, message, className = "") {
  element.textContent = message;
  element.className = `status ${className}`.trim();
}

function clearHostsTable() {
  discoveredHosts = [];
  hostsBody.innerHTML = "";
  hostCount = 0;
  selectedHostIp = null;
  lastScanSummary = null;
  hostFilterQuery = "";
  if (hostsFilterInput) {
    hostsFilterInput.value = "";
  }
  renderDiscoverySummary(null);
  updateHostsToolbar();
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
}

function setHostSort(column) {
  if (hostSort.column === column) {
    hostSort.direction = hostSort.direction === "asc" ? "desc" : "asc";
  } else {
    hostSort.column = column;
    hostSort.direction = column === "ip" ? "asc" : "asc";
  }
  updateHostSortHeaders();
  if (discoveredHosts.length > 0) {
    renderHostsTable();
  }
}

function clearPortsTable() {
  resetPortMonitor();
  portsBody.innerHTML = "";
  openPortCount = 0;
}

function formatServices(host) {
  if (host.device_role) {
    const title = host.mdns_services?.length
      ? ` title="${host.mdns_services
          .map((service) => {
            const source = service.source || service.name || "mdns";
            return `${service.hint} (${source})`;
          })
          .join(" · ")
          .replaceAll('"', "&quot;")}"`
      : "";
    return `<span class="service-hint"${title}>${escapeHtml(host.device_role)}</span>`;
  }
  return '<span class="service-hint missing">—</span>';
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

function setSelectedHost(ip) {
  selectedHostIp = ip;
  hostsBody.querySelectorAll("tr[data-host-ip]").forEach((row) => {
    row.classList.toggle("selected-host", row.dataset.hostIp === ip);
  });
  targetHostInput.value = ip;
  refreshPortProfileUi(ip, true);
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

  const hostname = host.hostname || "—";
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
    <td>${host.ip}${localBadge}${newBadge}</td>
    <td class="mono col-mac">${mac}</td>
    <td class="col-vendor">${vendor}${methodBadge}</td>
    <td class="col-hostname">${hostname}</td>
    <td>${services}</td>
    <td>${connection}</td>
    <td>${starlinkSignal}</td>
    <td class="col-os"${osTitle}>${osName}</td>
    <td><button type="button" class="secondary scan-host-btn" data-host="${host.ip}">Scan ports</button></td>
  `;

  row.addEventListener("click", (event) => {
    if (event.target.closest(".scan-host-btn")) {
      return;
    }
    setSelectedHost(host.ip);
  });

  row.querySelector(".scan-host-btn").addEventListener("click", (event) => {
    event.stopPropagation();
    setSelectedHost(host.ip);
    startPortScan(host.ip, getSelectedPorts());
  });

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
  row.innerHTML = `
    <td class="port-cell mono">${result.port}</td>
    <td>${result.service}</td>
    <td>${formatPortBanner(result.banner)}</td>
    <td>${result.state}</td>
    <td><button type="button" class="secondary monitor-port-btn">Monitor</button></td>
  `;

  row.addEventListener("dblclick", () => showPortInfo(result));
  row.querySelector(".monitor-port-btn").addEventListener("click", (event) => {
    event.stopPropagation();
    startPortMonitor(result);
  });
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
  portModalTitle.textContent = `Port ${result.port}`;
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
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && !portModal.classList.contains("hidden")) {
    closePortModal();
  }
});

function consumeEventStream(url, onEvent, onDone, onError) {
  const source = new EventSource(url);

  source.onmessage = (event) => {
    const payload = JSON.parse(event.data);
    onEvent(payload);
    if (payload.type === "done") {
      source.close();
      onDone();
    }
  };

  source.onerror = () => {
    source.close();
    onError();
  };

  return source;
}

function startDiscoveryScan() {
  if (discoverySource) {
    discoverySource.close();
  }

  clearHostsTable();
  scanNetworkBtn.disabled = true;
  setStatus(discoveryStatus, "Scanning local network for active hosts...", "scanning");

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
      scanNetworkBtn.disabled = false;
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
    },
    () => {
      scanNetworkBtn.disabled = false;
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
      scanPortsBtn.disabled = false;
      refreshHostServices(host);
      setStatus(
        portStatus,
        openPortCount
          ? `Port scan complete. ${openPortCount} open port${openPortCount === 1 ? "" : "s"} on ${host}.`
          : `Port scan complete. No open ports found on ${host}.`,
        "done",
      );
    },
    () => {
      scanPortsBtn.disabled = false;
      setStatus(portStatus, "Port scan failed.", "error");
    },
  );
}

scanNetworkBtn.addEventListener("click", startDiscoveryScan);

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
  refreshPortProfileUi(targetHostInput.value.trim());
});
targetHostInput.addEventListener("change", () => {
  refreshPortProfileUi(targetHostInput.value.trim(), true);
});
loadPortProfileBtn.addEventListener("click", () => {
  if (currentPortProfile?.ports) {
    applyPortProfile(currentPortProfile.ports);
    setStatus(portStatus, `Loaded saved profile: ${currentPortProfile.ports}`, "done");
  }
});
savePortProfileBtn.addEventListener("click", saveCurrentPortProfile);
clearPortProfileBtn.addEventListener("click", clearPortProfile);

updateHostSortHeaders();

portScanForm.addEventListener("submit", (event) => {
  event.preventDefault();
  startPortScan(targetHostInput.value.trim(), getSelectedPorts());
});

loadNetworkInfo();
