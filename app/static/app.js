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
const portModalConnect = document.getElementById("port-modal-connect");
const portModalConnectActions = document.getElementById("port-modal-connect-actions");
const portModalConnectNote = document.getElementById("port-modal-connect-note");
const portMonitorTitle = document.getElementById("port-monitor-title");
const portMonitorStopBtn = document.getElementById("port-monitor-stop-btn");
const portMonitorPanel = document.getElementById("port-monitor-panel");
const portMonitorStatus = document.getElementById("port-monitor-status");
const portMonitorStats = document.getElementById("port-monitor-stats");
const portMonitorLog = document.getElementById("port-monitor-log");

let discoverySource = null;
let portSource = null;
let monitorSource = null;
let activeMonitorPort = null;
let hostCount = 0;
let openPortCount = 0;

async function loadNetworkInfo() {
  const response = await fetch("/api/network");
  if (!response.ok) {
    networkInfo.textContent = "Network detection failed";
    return;
  }

  const data = await response.json();
  networkInfo.textContent = `${data.network} via ${data.interface} (${data.address})`;

  if (data.needs_setup) {
    setupNotice.classList.remove("hidden");
    setupMessage.textContent = data.message;
    setupCommand.textContent = data.setup_command;
  } else {
    setupNotice.classList.add("hidden");
  }
}

function setStatus(element, message, className = "") {
  element.textContent = message;
  element.className = `status ${className}`.trim();
}

function clearHostsTable() {
  hostsBody.innerHTML = "";
  hostCount = 0;
}

function clearPortsTable() {
  resetPortMonitor();
  portsBody.innerHTML = "";
  openPortCount = 0;
}

function addHostRow(host) {
  if (hostCount === 0) {
    hostsBody.innerHTML = "";
  }

  hostCount += 1;
  const row = document.createElement("tr");
  if (host.is_local) {
    row.classList.add("local-host");
  }

  const hostname = host.hostname || "—";
  const mac = host.mac || "—";
  const vendor = host.vendor || "—";
  const osName = host.os || "—";
  const osTitle = host.os_detail ? ` title="${host.os_detail.replaceAll('"', "&quot;")}"` : "";
  const localBadge = host.is_local ? '<span class="badge">this machine</span>' : "";
  const methodBadge = host.method
    ? `<span class="badge method">${host.method}</span>`
    : "";

  row.innerHTML = `
    <td>${host.ip}${localBadge}</td>
    <td class="mono">${mac}</td>
    <td>${vendor}${methodBadge}</td>
    <td>${hostname}</td>
    <td${osTitle}>${osName}</td>
    <td><button type="button" class="secondary scan-host-btn" data-host="${host.ip}">Scan Ports</button></td>
  `;

  row.querySelector(".scan-host-btn").addEventListener("click", () => {
    targetHostInput.value = host.ip;
    startPortScan(host.ip, getSelectedPorts());
  });

  hostsBody.appendChild(row);
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
      setStatus(
        discoveryStatus,
        hostCount
          ? `Discovery complete. Found ${hostCount} active host${hostCount === 1 ? "" : "s"}.`
          : "Discovery complete. No active hosts responded.",
        "done",
      );
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

portScanForm.addEventListener("submit", (event) => {
  event.preventDefault();
  startPortScan(targetHostInput.value.trim(), getSelectedPorts());
});

loadNetworkInfo();
