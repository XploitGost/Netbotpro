import { getFlowSummary, getPeerInfo, getTrafficSide, isLocalIp, isRemoteIp } from "./networkView";

const SERVICE_SIGNATURES = [
  { proto: "UDP", ports: [53], label: "DNS", confidence: 0.96, basis: "UDP/53", classification: "control lookup traffic" },
  { proto: "UDP", ports: [67, 68], label: "DHCP", confidence: 0.95, basis: "UDP/67-68", classification: "network bootstrap traffic" },
  { proto: "UDP", ports: [123], label: "NTP", confidence: 0.92, basis: "UDP/123", classification: "time sync traffic" },
  { proto: "UDP", ports: [500], label: "IKE / ISAKMP", confidence: 0.9, basis: "UDP/500", classification: "encrypted tunnel negotiation" },
  { proto: "UDP", ports: [4500], label: "IPsec NAT-T", confidence: 0.94, basis: "UDP/4500", classification: "encrypted UDP tunnel candidate" },
  { proto: "UDP", ports: [1194], label: "OpenVPN", confidence: 0.86, basis: "UDP/1194", classification: "encrypted tunnel candidate" },
  { proto: "UDP", ports: [1701], label: "L2TP", confidence: 0.84, basis: "UDP/1701", classification: "tunnel control traffic" },
  { proto: "UDP", ports: [3478], label: "STUN / TURN", confidence: 0.82, basis: "UDP/3478", classification: "traversal control traffic" },
  { proto: "UDP", ports: [5004, 5005], label: "RTP / RTCP", confidence: 0.7, basis: "UDP/5004-5005", classification: "media transport traffic" },
  { proto: "UDP", ports: [5060], label: "SIP", confidence: 0.7, basis: "UDP/5060", classification: "signaling traffic" },
  { proto: "UDP", ports: [51820], label: "WireGuard", confidence: 0.9, basis: "UDP/51820", classification: "encrypted tunnel candidate" },
  { proto: "TCP", ports: [22], label: "SSH", confidence: 0.94, basis: "TCP/22", classification: "encrypted remote access traffic" },
  { proto: "TCP", ports: [80], label: "HTTP", confidence: 0.96, basis: "TCP/80", classification: "web application traffic" },
  { proto: "TCP", ports: [443], label: "HTTPS / TLS", confidence: 0.97, basis: "TCP/443", classification: "encrypted web traffic" },
  { proto: "TCP", ports: [445], label: "SMB", confidence: 0.92, basis: "TCP/445", classification: "file-sharing traffic" },
  { proto: "TCP", ports: [3389], label: "RDP", confidence: 0.93, basis: "TCP/3389", classification: "interactive remote access traffic" },
];

const STANDARD_PROTOCOL_PORTS = {
  DNS: new Set([53, 5353, 853]),
  "DNS-over-TLS": new Set([853]),
  HTTP: new Set([80, 8000, 8080, 8081, 3000, 5000, 8008, 8888]),
  HTTPS: new Set([443, 8443, 9443]),
  TLS: new Set([443, 465, 563, 636, 853, 989, 990, 992, 993, 995, 8443, 9443]),
  QUIC: new Set([443, 784, 853]),
  "IPsec NAT-T": new Set([4500]),
  "IKE / ISAKMP": new Set([500]),
  WireGuard: new Set([51820]),
  OpenVPN: new Set([1194]),
  L2TP: new Set([1701]),
  "STUN / TURN": new Set([3478, 5349]),
};

function cleanText(value) {
  return String(value ?? "").trim();
}

function hasValue(value) {
  const text = cleanText(value);
  return Boolean(text) && text !== "-";
}

function sentenceCase(value) {
  const text = cleanText(value);
  if (!text) return "-";
  return text.charAt(0).toUpperCase() + text.slice(1);
}

function normalizeProto(value) {
  return cleanText(value).toUpperCase();
}

function normalizeDirection(value) {
  return normalizeProto(value);
}

function formatDirection(value) {
  const direction = normalizeDirection(value);
  if (direction === "INCOMING") return "Inbound";
  if (direction === "OUTGOING") return "Outbound";
  if (direction === "LOCAL") return "Local";
  return sentenceCase(value || "Unknown");
}

function parseTimestamp(value) {
  if (!value) return null;
  const direct = Date.parse(value);
  if (!Number.isNaN(direct)) return direct;
  const match = /^(\d{2}):(\d{2}):(\d{2})$/.exec(cleanText(value));
  if (!match) return null;
  const now = new Date();
  now.setHours(Number(match[1]), Number(match[2]), Number(match[3]), 0);
  return now.getTime();
}

function formatTimestamp(value) {
  const text = cleanText(value);
  return text || "-";
}

function formatDuration(ms) {
  if (!Number.isFinite(ms) || ms <= 0) return "0s";
  const totalSeconds = Math.round(ms / 1000);
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;
  if (hours > 0) return `${hours}h ${minutes}m ${seconds}s`;
  if (minutes > 0) return `${minutes}m ${seconds}s`;
  return `${seconds}s`;
}

function formatSignalScore(value) {
  const score = Number(value);
  const text = cleanText(value).toLowerCase();
  if (["high", "medium", "low"].includes(text)) return sentenceCase(text);
  if (!Number.isFinite(score)) return "-";
  if (score >= 0 && score <= 1) return formatPercent(score);
  if (score >= 10) return String(Math.round(score));
  return score.toFixed(2);
}

function normalizePort(value) {
  const numeric = Number(value);
  return Number.isInteger(numeric) && numeric > 0 ? numeric : null;
}

function formatPercent(score) {
  if (!Number.isFinite(score)) return "-";
  return `${Math.round(score * 100)}%`;
}

function formatNumber(value) {
  if (!Number.isFinite(value)) return "-";
  return new Intl.NumberFormat().format(value);
}

function formatList(value) {
  if (Array.isArray(value)) return value.length ? value.join(", ") : "-";
  const text = cleanText(value);
  return text || "-";
}

function readBool(value) {
  if (typeof value === "boolean") return value;
  const text = cleanText(value).toLowerCase();
  if (!text) return null;
  if (["true", "1", "yes"].includes(text)) return true;
  if (["false", "0", "no"].includes(text)) return false;
  return null;
}

function readNumber(value) {
  const numeric = Number(value);
  return Number.isFinite(numeric) ? numeric : null;
}

function confidenceFromSignal(value, fallback = 0.32) {
  if (typeof value === "number" && Number.isFinite(value)) {
    if (value >= 0 && value <= 1) return value;
    if (value > 1 && value <= 100) return Math.min(1, value / 100);
  }
  const text = cleanText(value).toLowerCase();
  if (text === "high") return 0.9;
  if (text === "medium") return 0.66;
  if (text === "low") return 0.38;
  return fallback;
}

function servicePort(packet) {
  const direction = normalizeDirection(packet?.direction);
  const sport = normalizePort(packet?.sport);
  const dport = normalizePort(packet?.dport);
  if (direction === "OUTGOING") return dport || sport;
  if (direction === "INCOMING") return sport || dport;
  return dport || sport;
}

function isProtocolGeneric(value) {
  return ["", "-", "TCP", "UDP", "ICMP", "OTHER"].includes(cleanText(value).toUpperCase());
}

function dnsTunnelLike(packet) {
  const qname = cleanText(packet?.dns_qname).replace(/\.+$/, "");
  if (!qname) return false;
  const labels = qname.split(".").filter(Boolean);
  const longestLabel = Math.max(0, ...labels.map((label) => label.length));
  const qtype = Number(packet?.dns_qtype || 0);
  return qname.length >= 52 || labels.length >= 5 || longestLabel >= 24 || qtype === 16;
}

function toRows(entries) {
  return entries.filter((entry) => hasValue(entry.value));
}

function decodeHexPreview(hexText) {
  const bytes = cleanText(hexText)
    .split(/\s+/)
    .map((part) => Number.parseInt(part, 16))
    .filter((value) => Number.isInteger(value) && value >= 0 && value <= 255);
  return bytes;
}

function computeEntropy(bytes) {
  if (!bytes.length) return 0;
  const counts = new Map();
  bytes.forEach((value) => counts.set(value, (counts.get(value) || 0) + 1));
  let entropy = 0;
  counts.forEach((count) => {
    const probability = count / bytes.length;
    entropy -= probability * Math.log2(probability);
  });
  return entropy;
}

function analyzePayload(packet) {
  const asciiPreview = cleanText(packet?.payload_ascii);
  const hexPreview = cleanText(packet?.payload_hex);
  const previewBytes = decodeHexPreview(hexPreview);
  const printableCount = asciiPreview ? asciiPreview.replace(/\./g, "").length : 0;
  const computedPrintableRatio = asciiPreview ? printableCount / asciiPreview.length : 0;
  const printableRatio = readNumber(packet?.payload_printable_ratio) ?? computedPrintableRatio;
  const computedEntropy = computeEntropy(previewBytes);
  const entropy = readNumber(packet?.payload_entropy) ?? computedEntropy;
  const persistedBinaryLike = readBool(packet?.payload_binary_like);
  const binaryLike = persistedBinaryLike ?? (Boolean(previewBytes.length) && (computedPrintableRatio < 0.45 || computedEntropy >= 4.3));
  let entropyHint = "No payload preview";
  if (previewBytes.length || readNumber(packet?.payload_entropy) != null) {
    if (entropy >= 4.6) entropyHint = "High entropy, likely encrypted or compressed";
    else if (entropy >= 3.2) entropyHint = "Mixed entropy, partially structured payload";
    else entropyHint = "Lower entropy, more human-readable payload";
  }
  return {
    printableRatio,
    entropy,
    entropyHint,
    binaryLike,
    tabs: [
      {
        id: "decoded",
        label: "Decoded",
        value:
          [hasValue(packet?.l7) ? `Layer decode: ${packet.l7}` : "", hasValue(packet?.summary) ? `Raw summary: ${packet.summary}` : ""]
            .filter(Boolean)
            .join("\n") || "No decoded payload available.",
      },
      {
        id: "ascii",
        label: "ASCII",
        value: asciiPreview || "No ASCII preview available.",
      },
      {
        id: "hex",
        label: "Hex",
        value: hexPreview || "No hex preview available.",
      },
    ],
  };
}

function serviceGuess(packet) {
  const proto = normalizeProto(packet?.proto);
  const appProtocol = cleanText(packet?.app_protocol);
  if (appProtocol && !isProtocolGeneric(appProtocol)) {
    return {
      label: appProtocol,
      confidence: confidenceFromSignal(packet?.app_confidence, 0.82),
      basis: cleanText(packet?.protocol_basis) || "Application decode",
      classification: `${appProtocol.toLowerCase()} traffic`,
    };
  }

  if (hasValue(packet?.dns_qname)) {
    return { label: "DNS", confidence: 0.94, basis: "Layer-7 decode", classification: "control lookup traffic" };
  }
  if (hasValue(packet?.http_host) || hasValue(packet?.http_method)) {
    return { label: "HTTP", confidence: 0.94, basis: "Layer-7 decode", classification: "web application traffic" };
  }
  if (hasValue(packet?.tls_version) || hasValue(packet?.tls_sni) || hasValue(packet?.ja3) || hasValue(packet?.ja4)) {
    return { label: "TLS", confidence: 0.9, basis: "TLS metadata", classification: "encrypted application traffic" };
  }

  const l7 = cleanText(packet?.l7).toUpperCase();
  if (l7.startsWith("DNS")) {
    return { label: "DNS", confidence: 0.94, basis: "Layer-7 decode", classification: "control lookup traffic" };
  }
  if (l7.startsWith("HTTP")) {
    return { label: "HTTP", confidence: 0.94, basis: "Layer-7 decode", classification: "web application traffic" };
  }
  if (l7 === "TLS") {
    return { label: "TLS", confidence: 0.9, basis: "TLS fingerprinting", classification: "encrypted application traffic" };
  }

  const ports = [normalizePort(packet?.dport), normalizePort(packet?.sport)].filter(Boolean);
  const match = SERVICE_SIGNATURES.find((item) => item.proto === proto && item.ports.some((port) => ports.includes(port)));
  return match || { label: proto || "Unknown transport", confidence: 0.32, basis: "Transport metadata only", classification: "unclassified traffic" };
}

function protocolSignals(packet, guess, payload) {
  const label = cleanText(guess?.label) || normalizeProto(packet?.proto) || "Unknown";
  const servicePortValue = servicePort(packet);
  const standardPorts = STANDARD_PROTOCOL_PORTS[label] || new Set();
  const explicitUnusualPort = readBool(packet?.protocol_unusual_port);
  const unusualPort = explicitUnusualPort ?? Boolean(servicePortValue && standardPorts.size && !standardPorts.has(servicePortValue));
  const notes = [];
  const packetNotes = cleanText(packet?.protocol_notes);
  if (packetNotes) notes.push(packetNotes);
  if (dnsTunnelLike(packet)) notes.push("DNS query shape looks tunnel-like or unusually long.");
  if (unusualPort && servicePortValue) notes.push(`${label} metadata was observed on non-standard port ${servicePortValue}.`);
  const handshake =
    cleanText(packet?.protocol_handshake) ||
    (hasValue(packet?.tls_version) || hasValue(packet?.ja3) || hasValue(packet?.ja4)
      ? "TLS ClientHello"
      : hasValue(packet?.http_method)
        ? "HTTP request"
        : hasValue(packet?.http_status)
          ? "HTTP response"
          : hasValue(packet?.dns_qname)
            ? "DNS question"
            : label === "QUIC"
              ? "QUIC candidate"
              : label === "IPsec NAT-T"
                ? "NAT-T tunnel candidate"
                : "");
  const basisParts = [];
  const packetBasis = cleanText(packet?.protocol_basis);
  if (packetBasis) basisParts.push(packetBasis);
  else {
    if (hasValue(packet?.dns_qname)) basisParts.push("Payload decode: DNS question");
    else if (hasValue(packet?.http_method)) basisParts.push("Payload decode: HTTP request line");
    else if (hasValue(packet?.http_status)) basisParts.push("Payload decode: HTTP response");
    else if (hasValue(packet?.tls_version)) basisParts.push(`TLS handshake: ${packet.tls_version}`);
    else if (hasValue(packet?.ja3) || hasValue(packet?.ja4)) basisParts.push("TLS fingerprint metadata present");
  }
  if (handshake && !basisParts.some((part) => part.includes(handshake))) basisParts.push(handshake);
  if (guess?.basis && guess.basis !== "Application decode" && guess.basis !== packetBasis) basisParts.push(guess.basis);
  if (unusualPort && servicePortValue) basisParts.push(`Observed on unusual port ${servicePortValue}`);

  const encrypted =
    readBool(packet?.payload_binary_like) ??
    payload.binaryLike ??
    Boolean(hasValue(packet?.tls_version) || ["TLS", "HTTPS", "QUIC", "IPsec NAT-T", "WireGuard", "OpenVPN"].includes(label));

  return {
    servicePort: servicePortValue,
    unusualPort,
    unusualPortLabel: unusualPort ? `Yes, port ${servicePortValue}` : "No",
    basis: [...new Set(basisParts.filter(Boolean))].join(" | ") || guess?.basis || "Transport metadata only",
    notes: [...new Set(notes.filter(Boolean))],
    notesText: [...new Set(notes.filter(Boolean))].join(" "),
    handshake: handshake || "No handshake marker captured",
    encrypted,
    encryptedLabel: encrypted ? "Likely encrypted or binary" : "Mostly structured / printable",
  };
}

function packetClassification(packet, guess, payload, signals) {
  const proto = normalizeProto(packet?.proto);
  const flags = cleanText(packet?.flags).toUpperCase();
  if (cleanText(packet?.attack_type)) return "alert-linked traffic";
  if (dnsTunnelLike(packet)) return "dns tunnel-like activity";
  if (guess.label === "IPsec NAT-T") return "encrypted UDP tunnel candidate";
  if (guess.label === "QUIC") return signals.unusualPort ? "QUIC on unusual port" : "QUIC / HTTP/3 candidate";
  if (guess.label === "TLS" && signals.unusualPort) return "TLS on unusual port";
  if (guess.label === "HTTP" && signals.unusualPort) return "cleartext HTTP on unusual port";
  if (guess.label === "DNS" && signals.unusualPort) return "DNS on unusual port";
  if (guess.classification && guess.classification !== "unclassified traffic") return guess.classification;
  if (proto === "TCP" && flags.includes("S") && !flags.includes("A")) return "handshake candidate";
  if (proto === "UDP" && payload.binaryLike) return "binary UDP payload";
  if (proto === "ICMP") return "control plane traffic";
  if (cleanText(packet?.app_category) === "web") return "web application traffic";
  if (cleanText(packet?.tls_version)) return "encrypted application traffic";
  return "unknown packet role";
}

function processSummary(packet) {
  const processName = cleanText(packet?.process_name);
  const pid = cleanText(packet?.pid);
  const confidence = sentenceCase(packet?.attribution_confidence || "");
  const attributionSource = cleanText(packet?.attribution_source);
  const parentProcess = cleanText(packet?.parent_process_name);
  const executablePath = cleanText(packet?.executable_path);
  if (processName || pid) {
    const hints = [
      pid && processName ? `PID ${pid}` : "",
      confidence ? `${confidence} confidence` : "",
      attributionSource ? `Source: ${attributionSource}` : "",
      parentProcess ? `Parent: ${parentProcess}` : "",
      executablePath || "",
    ].filter(Boolean);
    return {
      label: processName || `PID ${pid}`,
      hint: hints.join(" | ") || "Mapped from active socket",
      reasonUnavailable: "",
      confidenceLabel: confidence || (processName && pid ? "High" : "Medium"),
    };
  }
  const direction = normalizeDirection(packet?.direction);
  let reasonUnavailable = cleanText(packet?.attribution_reason_unavailable) || "No active socket match / kernel-owned / stale mapping.";
  if (direction === "OUTGOING") {
    reasonUnavailable = cleanText(packet?.attribution_reason_unavailable) || "No active socket match / short-lived socket / attribution window expired.";
  } else if (direction === "LOCAL") {
    reasonUnavailable = cleanText(packet?.attribution_reason_unavailable) || "No socket attribution available for local-only traffic.";
  }
  return {
    label: "Unknown process",
    hint: "Process attribution unavailable",
    reasonUnavailable,
    confidenceLabel: confidence || "Unavailable",
  };
}

function determineEndpoints(packet) {
  const src = cleanText(packet?.src) || "-";
  const dst = cleanText(packet?.dst) || "-";
  const direction = normalizeDirection(packet?.direction);
  const peer = getPeerInfo(packet);
  const srcSide = getTrafficSide(src);
  const dstSide = getTrafficSide(dst);

  let localEndpoint = isLocalIp(src) && !isLocalIp(dst) ? src : isLocalIp(dst) ? dst : srcSide.label === "LAN" ? src : dst;
  let remoteEndpoint = peer.ip && peer.ip !== "-" ? peer.ip : src === localEndpoint ? dst : src;

  if (direction === "INCOMING") {
    localEndpoint = dst;
    remoteEndpoint = src;
  } else if (direction === "OUTGOING") {
    localEndpoint = src;
    remoteEndpoint = dst;
  }

  return {
    localEndpoint: localEndpoint || "-",
    remoteEndpoint: remoteEndpoint || "-",
    localZone: getTrafficSide(localEndpoint).label,
    remoteZone: getTrafficSide(remoteEndpoint).label,
    peer,
    srcSide,
    dstSide,
  };
}

function resolveConversationPorts(packet, endpoints = determineEndpoints(packet)) {
  const src = cleanText(packet?.src);
  const direction = normalizeDirection(packet?.direction);
  const srcPort = normalizePort(packet?.sport);
  const dstPort = normalizePort(packet?.dport);

  if (direction === "INCOMING") {
    return { localPort: dstPort, remotePort: srcPort };
  }
  if (direction === "OUTGOING") {
    return { localPort: srcPort, remotePort: dstPort };
  }
  if (endpoints.localEndpoint === src) {
    return { localPort: srcPort, remotePort: dstPort };
  }
  return { localPort: dstPort, remotePort: srcPort };
}

function buildConversationKey(packet) {
  const endpoints = determineEndpoints(packet);
  const ports = resolveConversationPorts(packet, endpoints);
  const proto = normalizeProto(packet?.proto) || "OTHER";
  return `${endpoints.localEndpoint}:${ports.localPort || "-"} <-> ${endpoints.remoteEndpoint}:${ports.remotePort || "-"} (${proto})`;
}

function sameConversation(left, right) {
  if (!left || !right) return false;
  const leftEndpoints = determineEndpoints(left);
  const rightEndpoints = determineEndpoints(right);
  const leftPorts = resolveConversationPorts(left, leftEndpoints);
  const rightPorts = resolveConversationPorts(right, rightEndpoints);
  return (
    normalizeProto(left?.proto) === normalizeProto(right?.proto) &&
    cleanText(leftEndpoints.localEndpoint) === cleanText(rightEndpoints.localEndpoint) &&
    cleanText(leftEndpoints.remoteEndpoint) === cleanText(rightEndpoints.remoteEndpoint) &&
    leftPorts.localPort === rightPorts.localPort &&
    leftPorts.remotePort === rightPorts.remotePort
  );
}

function sameRemoteEndpoint(left, right) {
  return cleanText(determineEndpoints(left).remoteEndpoint) === cleanText(determineEndpoints(right).remoteEndpoint);
}

function timestampValues(rows, selectedTs) {
  const values = rows
    .map((row) => ({ ts: row?.ts, value: parseTimestamp(row?.ts) }))
    .filter((entry) => Number.isFinite(entry.value))
    .sort((left, right) => left.value - right.value);
  const selectedValue = parseTimestamp(selectedTs);
  if (Number.isFinite(selectedValue) && !values.some((entry) => entry.value === selectedValue)) {
    values.push({ ts: selectedTs, value: selectedValue });
    values.sort((left, right) => left.value - right.value);
  }
  return values;
}

function relatedAlertMatch(alert, packet, relatedPacketIds) {
  if (!alert || !packet) return false;
  const packetId = cleanText(alert?.packet_id);
  if (packetId && relatedPacketIds.has(packetId)) return true;
  const sameProto = !hasValue(alert?.proto) || normalizeProto(alert?.proto) === normalizeProto(packet?.proto);
  const alertSrc = cleanText(alert?.src);
  const alertDst = cleanText(alert?.dst);
  const packetSrc = cleanText(packet?.src);
  const packetDst = cleanText(packet?.dst);
  return sameProto && ((alertSrc === packetSrc && alertDst === packetDst) || (alertSrc === packetDst && alertDst === packetSrc));
}

function packetSampleRows(packet, packetRows = []) {
  const selectedId = cleanText(packet?.id);
  const rows = Array.isArray(packetRows) ? packetRows.filter(Boolean) : [];
  if (selectedId && rows.some((row) => cleanText(row?.id) === selectedId)) return rows;
  return packet ? [packet, ...rows] : rows;
}

function stableFlowId(identity) {
  return `sample-flow-${[identity?.proto || "OTHER", identity?.localIp || "-", identity?.localPort ?? "-", identity?.remoteIp || "-", identity?.remotePort ?? "-"]
    .map((value) => String(value).replace(/\s+/g, "_"))
    .join("-")}`;
}

function packetFlowIdentity(packet) {
  const endpoints = determineEndpoints(packet);
  const ports = resolveConversationPorts(packet, endpoints);
  const src = cleanText(packet?.src);
  const dst = cleanText(packet?.dst);
  let direction = normalizeDirection(packet?.direction);
  if (!direction) {
    if (isLocalIp(src) && !isLocalIp(dst)) direction = "OUTGOING";
    else if (isLocalIp(dst) && !isLocalIp(src)) direction = "INCOMING";
    else direction = "UNKNOWN";
  }

  const identity = {
    proto: normalizeProto(packet?.proto) || "OTHER",
    direction,
    localIp: cleanText(endpoints.localEndpoint) || "-",
    remoteIp: cleanText(endpoints.remoteEndpoint) || "-",
    localPort: ports.localPort,
    remotePort: ports.remotePort,
    conversationKey: buildConversationKey(packet),
  };
  return {
    ...identity,
    flowId: stableFlowId(identity),
  };
}

function samePeerIdentity(left, right) {
  return left.proto === right.proto && left.localIp === right.localIp && left.remoteIp === right.remoteIp;
}

function sameFlowIdentity(left, right) {
  return samePeerIdentity(left, right) && left.localPort === right.localPort && left.remotePort === right.remotePort;
}

function samePortIdentity(left, right) {
  if (!samePeerIdentity(left, right)) return false;
  const sharedPorts = new Set([right.localPort, right.remotePort].filter((port) => Number.isInteger(port)));
  return [left.localPort, left.remotePort].some((port) => sharedPorts.has(port));
}

function uniqueNonEmpty(values) {
  return [...new Set((values || []).map((value) => cleanText(value)).filter((value) => value && value !== "-"))].sort();
}

function buildProcessCorrelationSample(packet, packetRows, alertRows = []) {
  const pid = cleanText(packet?.pid);
  const processName = cleanText(packet?.process_name);
  const attributionConfidence = cleanText(packet?.attribution_confidence) || "unavailable";
  const attributionSource = cleanText(packet?.attribution_source);
  const reasonUnavailable =
    cleanText(packet?.attribution_reason_unavailable) || "Process metadata is unavailable for this packet or not persisted in history.";
  if (!pid && !processName) {
    return {
      available: false,
      label: "Unknown process",
      pid: null,
      parent_pid: packet?.parent_pid ?? null,
      parent_process_name: cleanText(packet?.parent_process_name) || null,
      executable_path: cleanText(packet?.executable_path) || null,
      attribution_confidence: attributionConfidence,
      attribution_source: attributionSource || null,
      reason_unavailable: reasonUnavailable,
    };
  }

  const rows = packetRows.filter((row) => {
    const rowPid = cleanText(row?.pid);
    const rowName = cleanText(row?.process_name);
    if (pid && rowPid) return rowPid === pid;
    if (processName && rowName) return rowName.toLowerCase() === processName.toLowerCase();
    return false;
  });
  const processAlerts = (Array.isArray(alertRows) ? alertRows : []).filter((row) => {
    const rowPid = cleanText(row?.pid);
    const rowName = cleanText(row?.process_name);
    if (pid && rowPid) return rowPid === pid;
    if (processName && rowName) return rowName.toLowerCase() === processName.toLowerCase();
    return false;
  });
  const identities = rows.map((row) => packetFlowIdentity(row));
  const sessionIds = new Set(identities.map((identity) => identity.flowId));
  const uniquePorts = uniqueNonEmpty([
    ...identities.map((identity) => identity.localPort),
    ...identities.map((identity) => identity.remotePort),
  ]);
  const remoteHosts = uniqueNonEmpty(identities.map((identity) => identity.remoteIp));
  const seenFlows = new Set();
  const flowSamples = [];
  identities.forEach((identity) => {
    if (flowSamples.length >= 4 || seenFlows.has(identity.flowId)) return;
    seenFlows.add(identity.flowId);
    flowSamples.push({
      title: identity.conversationKey,
      body: `${formatDirection(identity.direction)} session`,
    });
  });

  let pattern = "Single-session process activity";
  if (sessionIds.size >= 3 && uniquePorts.length >= 3 && remoteHosts.length >= 3) pattern = "Multi-port multi-host process activity";
  else if (sessionIds.size >= 3) pattern = "Process appears across multiple sessions";

  const selectedPacketId = cleanText(packet?.id);
  const relatedPackets = rows
    .filter((row) => cleanText(row?.id) !== selectedPacketId)
    .slice(0, 5)
    .map((row) => ({
      id: row?.id,
      ts: row?.ts,
      src: row?.src,
      dst: row?.dst,
      proto: row?.proto,
      sport: row?.sport,
      dport: row?.dport,
      summary: row?.summary,
    }));

  return {
    available: true,
    label: processName || `PID ${pid}`,
    pid: pid || null,
    parent_pid: packet?.parent_pid ?? null,
    parent_process_name: cleanText(packet?.parent_process_name) || null,
    executable_path: cleanText(packet?.executable_path) || null,
    attribution_confidence: attributionConfidence === "unavailable" ? "medium" : attributionConfidence,
    attribution_source: attributionSource || null,
    reason_unavailable: null,
    packets_total: rows.length,
    alerts_total: processAlerts.length,
    sessions_total: sessionIds.size,
    ports_total: uniquePorts.length,
    remote_hosts_total: remoteHosts.length,
    pattern,
    flow_samples: flowSamples,
    related_packets: relatedPackets,
    related_alerts: processAlerts.slice(0, 5).map((row) => ({
      id: row?.id,
      ts: row?.ts,
      attack_type: row?.attack_type,
      severity: row?.severity,
      detail: row?.detail,
    })),
  };
}

function buildHostCorrelationSample(packet, packetRows) {
  const selectedIdentity = packetFlowIdentity(packet);
  const identities = packetRows
    .map((row) => packetFlowIdentity(row))
    .filter((identity) => identity.localIp === selectedIdentity.localIp);
  const uniqueRemotes = uniqueNonEmpty(identities.map((identity) => identity.remoteIp));
  const uniqueSessions = new Set(identities.map((identity) => identity.flowId));
  const uniqueRemotePorts = uniqueNonEmpty(identities.map((identity) => identity.remotePort));
  const selectedRemoteSessions = new Set(identities.filter((identity) => identity.remoteIp === selectedIdentity.remoteIp).map((identity) => identity.flowId));
  const timestamps = packetRows
    .filter((row) => packetFlowIdentity(row).localIp === selectedIdentity.localIp)
    .map((row) => parseTimestamp(row?.ts))
    .filter((value) => Number.isFinite(value));
  let burstPackets = 0;
  if (timestamps.length) {
    const latest = Math.max(...timestamps);
    burstPackets = timestamps.filter((value) => latest - value <= 10_000).length;
  }

  let pattern = "Focused host activity";
  if (uniqueRemotes.length >= 5) pattern = "Fan-out pattern observed";
  else if (burstPackets >= 6) pattern = "Burst pattern observed";
  else if (selectedRemoteSessions.size >= 3) pattern = "Remote peer appears across multiple sessions";

  return {
    local_ip: selectedIdentity.localIp,
    remote_hosts_total: uniqueRemotes.length,
    sessions_total: uniqueSessions.size,
    remote_ports_total: uniqueRemotePorts.length,
    selected_remote_sessions_total: selectedRemoteSessions.size,
    burst_packets_10s: burstPackets,
    pattern,
  };
}

function buildPortCorrelationSample(packet, packetRows) {
  const selectedIdentity = packetFlowIdentity(packet);
  const identities = packetRows
    .map((row) => packetFlowIdentity(row))
    .filter((identity) => identity.localIp === selectedIdentity.localIp && identity.proto === selectedIdentity.proto);
  const sameLocalPort = identities.filter((identity) => selectedIdentity.localPort != null && identity.localPort === selectedIdentity.localPort);
  const sameRemotePort = identities.filter((identity) => selectedIdentity.remotePort != null && identity.remotePort === selectedIdentity.remotePort);
  const localPortSessions = new Set(sameLocalPort.map((identity) => identity.flowId));
  const localPortRemotes = new Set(sameLocalPort.map((identity) => identity.remoteIp));
  const remotePortSessions = new Set(sameRemotePort.map((identity) => identity.flowId));
  const remotePortRemotes = new Set(sameRemotePort.map((identity) => identity.remoteIp));

  let pattern = "Port usage stays narrow";
  if (remotePortRemotes.size >= 4) pattern = "Sweep pattern candidate";
  else if (localPortSessions.size >= 3) pattern = "Local port reuse across sessions";
  else if (remotePortSessions.size >= 3) pattern = "Remote service reuse across sessions";

  return {
    local_port: selectedIdentity.localPort,
    remote_port: selectedIdentity.remotePort,
    local_port_sessions_total: localPortSessions.size,
    local_port_remote_hosts_total: localPortRemotes.size,
    remote_port_sessions_total: remotePortSessions.size,
    remote_port_remote_hosts_total: remotePortRemotes.size,
    pattern,
  };
}

function buildConversationClustersSample(packet, packetRows) {
  const selectedIdentity = packetFlowIdentity(packet);
  const hostPackets = packetRows.filter((row) => packetFlowIdentity(row).localIp === selectedIdentity.localIp);
  const clusters = new Map();

  hostPackets.forEach((row) => {
    const identity = packetFlowIdentity(row);
    const key = `${identity.proto}|${identity.remoteIp}`;
    if (!clusters.has(key)) {
      clusters.set(key, {
        proto: identity.proto,
        remoteIp: identity.remoteIp,
        sessionIds: new Set(),
        packetsTotal: 0,
        ports: new Set(),
      });
    }
    const cluster = clusters.get(key);
    cluster.sessionIds.add(identity.flowId);
    cluster.packetsTotal += 1;
    if (identity.remotePort != null) cluster.ports.add(identity.remotePort);
  });

  return [...clusters.values()]
    .sort((left, right) => {
      const sessionDelta = right.sessionIds.size - left.sessionIds.size;
      if (sessionDelta !== 0) return sessionDelta;
      return right.packetsTotal - left.packetsTotal;
    })
    .slice(0, 5)
    .map((cluster) => ({
      title: `${cluster.remoteIp} (${cluster.proto})`,
      body: `${cluster.sessionIds.size} sessions | ${cluster.packetsTotal} packets | ports ${[...cluster.ports].sort((left, right) => left - right).join(", ") || "-"}`,
    }));
}

function buildBehaviorLabelsSample(packet, packetRows, flowPackets) {
  const labels = [];
  const host = buildHostCorrelationSample(packet, packetRows);
  const port = buildPortCorrelationSample(packet, packetRows);
  const process = buildProcessCorrelationSample(packet, packetRows);
  if (host?.pattern && host.pattern !== "Focused host activity") labels.push(host.pattern);
  if (port?.pattern && port.pattern !== "Port usage stays narrow") labels.push(port.pattern);
  if (process?.available && process?.pattern && process.pattern !== "Single-session process activity") labels.push(process.pattern);
  const flowTimes = (flowPackets || []).map((row) => parseTimestamp(row?.ts)).filter((value) => Number.isFinite(value));
  if ((flowPackets || []).length >= 6 && flowTimes.length && Math.max(...flowTimes) - Math.min(...flowTimes) <= 30_000) {
    labels.push("Burst pattern observed");
  }
  return [...new Set(labels)].slice(0, 5);
}

function buildRelatedFlowsSample(packet, packetRows = []) {
  const selectedIdentity = packetFlowIdentity(packet);
  const grouped = new Map();
  packetRows.forEach((row) => {
    const identity = packetFlowIdentity(row);
    if (identity.flowId === selectedIdentity.flowId) return;
    if (identity.localIp !== selectedIdentity.localIp && identity.remoteIp !== selectedIdentity.remoteIp) return;
    if (!grouped.has(identity.flowId)) {
      grouped.set(identity.flowId, {
        title: identity.conversationKey,
        direction: identity.direction,
        remoteIp: identity.remoteIp,
        packetsTotal: 0,
        ports: new Set(),
      });
    }
    const current = grouped.get(identity.flowId);
    current.packetsTotal += 1;
    if (identity.remotePort != null) current.ports.add(identity.remotePort);
  });
  return [...grouped.values()]
    .sort((left, right) => right.packetsTotal - left.packetsTotal)
    .slice(0, 5)
    .map((item) => ({
      title: item.title,
      body: `${item.packetsTotal} packets | ${formatDirection(item.direction)} | remote ${item.remoteIp} | ports ${[...item.ports].sort((left, right) => left - right).join(", ") || "-"}`,
    }));
}

function buildSameRemoteActivitySample(packet, packetRows = [], alertRows = []) {
  const selectedIdentity = packetFlowIdentity(packet);
  const selectedPacketId = cleanText(packet?.id);
  const sameRemotePackets = packetRows
    .filter((row) => packetFlowIdentity(row).remoteIp === selectedIdentity.remoteIp && cleanText(row?.id) !== selectedPacketId)
    .slice(0, 5);
  const sameRemoteAlerts = alertRows
    .filter((row) => packetFlowIdentity(row).remoteIp === selectedIdentity.remoteIp)
    .slice(0, 5);
  return { sameRemotePackets, sameRemoteAlerts };
}

function buildAlertCorrelationSample(flowAlerts = [], peerAlerts = [], sameRemoteAlerts = []) {
  return {
    flow_alerts_total: flowAlerts.length,
    peer_alerts_total: peerAlerts.length,
    same_remote_alerts_total: sameRemoteAlerts.length,
    engines: [...new Set(peerAlerts.map((row) => cleanText(row?.engine)).filter(Boolean))],
    attack_types: [...new Set(peerAlerts.map((row) => cleanText(row?.attack_type)).filter(Boolean))],
    incident_ids: [...new Set(peerAlerts.map((row) => cleanText(row?.incident_id)).filter(Boolean))],
  };
}

function buildRootCauseGroupsSample({ processCorrelation, alertCorrelation, behaviorLabels, relatedFlows, linkedPacketSummary = null }) {
  const groups = [];
  if (linkedPacketSummary) {
    groups.push({
      title: "Packet to Alert Chain",
      body: `Alert links to packet ${cleanText(linkedPacketSummary?.id || linkedPacketSummary?.capture_id) || "-"} on ${normalizeProto(linkedPacketSummary?.proto) || "OTHER"} ${cleanText(linkedPacketSummary?.sport) || "-"} -> ${cleanText(linkedPacketSummary?.dport) || "-"}.`,
    });
  }
  if (Number(alertCorrelation?.flow_alerts_total || 0) > 0) {
    groups.push({
      title: "Flow-linked Detections",
      body: `${formatNumber(Number(alertCorrelation.flow_alerts_total || 0))} alert(s) were observed on the same flow; attack types: ${alertCorrelation?.attack_types?.join(", ") || "-"}.`,
    });
  }
  if (Number(alertCorrelation?.peer_alerts_total || 0) > Number(alertCorrelation?.flow_alerts_total || 0)) {
    groups.push({
      title: "Remote Host Recurrence",
      body: `The same peer triggered ${formatNumber(Number(alertCorrelation.peer_alerts_total || 0))} alert(s) in the current investigation window.`,
    });
  }
  if (processCorrelation?.available && Number(processCorrelation?.alerts_total || 0) > 0) {
    groups.push({
      title: "Process-linked Activity",
      body: `${cleanText(processCorrelation?.label) || "Process"} appears across ${formatNumber(Number(processCorrelation?.sessions_total || 0))} sessions and ${formatNumber(Number(processCorrelation?.alerts_total || 0))} alert(s).`,
    });
  }
  if (Array.isArray(behaviorLabels) && behaviorLabels.length) {
    groups.push({
      title: "Behavior Pattern",
      body: `Observed pattern(s): ${behaviorLabels.join(", ")}.`,
    });
  }
  if (Array.isArray(relatedFlows) && relatedFlows.length) {
    groups.push({
      title: "Related Flow Cluster",
      body: `${formatNumber(relatedFlows.length)} additional flow(s) share the same host or remote context.`,
    });
  }
  return groups.slice(0, 5);
}

export function buildPacketInspectionContext(packet, packets = [], alerts = []) {
  if (!packet) return {};

  const packetRows = packetSampleRows(packet, packets);
  const alertRows = Array.isArray(alerts) ? alerts.filter(Boolean) : [];
  const selectedIdentity = packetFlowIdentity(packet);
  const packetIdentities = packetRows.map((row) => ({ row, identity: packetFlowIdentity(row) }));
  const relatedPackets = packetIdentities.filter(({ identity }) => sameFlowIdentity(identity, selectedIdentity)).map(({ row }) => row);
  const peerPackets = packetIdentities.filter(({ identity }) => samePeerIdentity(identity, selectedIdentity)).map(({ row }) => row);
  const samePortCount = packetIdentities.filter(({ identity }) => samePortIdentity(identity, selectedIdentity)).length;

  const relatedPacketIds = new Set(
    [packet, ...relatedPackets]
      .map((row) => cleanText(row?.id))
      .filter(Boolean)
  );
  const flowAlerts = alertRows.filter((alert) => relatedAlertMatch(alert, packet, relatedPacketIds));
  const peerAlerts = alertRows.filter((alert) => {
    const alertIdentity = packetFlowIdentity(alert);
    return samePeerIdentity(alertIdentity, selectedIdentity);
  });

  const timeRows = timestampValues(relatedPackets.length ? relatedPackets : [packet], packet?.ts);
  const firstSeen = timeRows[0]?.ts || packet?.ts;
  const lastSeen = timeRows[timeRows.length - 1]?.ts || packet?.ts;
  const firstValue = timeRows[0]?.value;
  const lastValue = timeRows[timeRows.length - 1]?.value;
  const selectedValue = parseTimestamp(packet?.ts);
  let previousPacketDeltaMs = null;
  if (Number.isFinite(selectedValue)) {
    const previous = [...timeRows].reverse().find((entry) => entry.value < selectedValue);
    if (previous) previousPacketDeltaMs = selectedValue - previous.value;
  }

  const processCorrelation = buildProcessCorrelationSample(packet, packetRows, alertRows);
  const hostCorrelation = buildHostCorrelationSample(packet, packetRows);
  const portCorrelation = buildPortCorrelationSample(packet, packetRows);
  const conversationClusters = buildConversationClustersSample(packet, packetRows);
  const behaviorLabels = buildBehaviorLabelsSample(packet, packetRows, relatedPackets);
  const relatedFlows = buildRelatedFlowsSample(packet, packetRows);
  const { sameRemotePackets, sameRemoteAlerts } = buildSameRemoteActivitySample(packet, packetRows, alertRows);
  const alertCorrelation = buildAlertCorrelationSample(flowAlerts, peerAlerts, sameRemoteAlerts);
  const rootCauseGroups = buildRootCauseGroupsSample({
    processCorrelation,
    alertCorrelation,
    behaviorLabels,
    relatedFlows,
  });

  return {
    source: "frontend-sample",
    flow_id: selectedIdentity.flowId,
    conversation_key: selectedIdentity.conversationKey,
    direction: selectedIdentity.direction,
    local_ip: selectedIdentity.localIp,
    remote_ip: selectedIdentity.remoteIp,
    local_port: selectedIdentity.localPort,
    remote_port: selectedIdentity.remotePort,
    flow_packets_total: Math.max(1, relatedPackets.length || 0),
    flow_alerts_total: flowAlerts.length,
    same_peer_packets_total: peerPackets.length,
    same_peer_alerts_total: peerAlerts.length,
    same_port_packets_total: samePortCount,
    flow_bytes_in: relatedPackets.reduce((total, row) => total + Math.max(0, Number(row?.direction === "INCOMING" ? row?.length || 0 : 0)), 0),
    flow_bytes_out: relatedPackets.reduce((total, row) => total + Math.max(0, Number(row?.direction !== "INCOMING" ? row?.length || 0 : 0)), 0),
    first_seen: firstSeen,
    last_seen: lastSeen,
    duration_ms: Number.isFinite(firstValue) && Number.isFinite(lastValue) ? Math.max(0, lastValue - firstValue) : 0,
    previous_packet_delta_ms: previousPacketDeltaMs,
    sample_packets: packetRows.length,
    sample_alerts: alertRows.length,
    behavior_labels: behaviorLabels,
    process_correlation: processCorrelation,
    host_correlation: hostCorrelation,
    port_correlation: portCorrelation,
    conversation_clusters: conversationClusters,
    related_flows: relatedFlows,
    same_remote_packets: sameRemotePackets,
    same_remote_alerts: sameRemoteAlerts,
    alert_correlation: alertCorrelation,
    root_cause_groups: rootCauseGroups,
    related_packets: relatedPackets.filter((row) => cleanText(row?.id) !== cleanText(packet?.id)).slice(0, 5),
    related_alerts: flowAlerts.slice(0, 5),
  };
}

export function buildCaptureInspectionContext({ packetMeta, settings, interfaces, capturePreflight, sniffer }) {
  const selectedIface = cleanText(sniffer?.iface || settings?.iface);
  const interfaceList = Array.isArray(interfaces) ? interfaces : [];
  const ifaceEntry = interfaceList.find((item) => cleanText(item?.value) === selectedIface || cleanText(item?.label) === selectedIface || cleanText(item?.name) === selectedIface);
  const source = cleanText(packetMeta?.source);
  let sourceLabel = "-";
  if (source === "memory") sourceLabel = "Live capture window";
  else if (source === "sqlite") sourceLabel = "Persisted history";
  else if (source) sourceLabel = sentenceCase(source);

  return {
    iface: cleanText(sniffer?.iface || ifaceEntry?.label || capturePreflight?.recommended_interface_label || selectedIface) || "-",
    interfaceAlias: cleanText(ifaceEntry?.name || ifaceEntry?.network_name) || "-",
    source: sourceLabel,
    engine: cleanText(capturePreflight?.provider) || "-",
  };
}

export function buildAlertInspectionContext(alert, packets = [], alerts = []) {
  if (!alert) return {};

  const linkedPacket = packets.find((packet) => cleanText(packet?.capture_id || packet?.id) === cleanText(alert?.packet_id));
  const anchor = linkedPacket || {
    ...alert,
    proto: alert?.proto,
    src: alert?.src,
    dst: alert?.dst,
    sport: alert?.sport,
    dport: alert?.dport,
    direction: alert?.direction,
    remote_ip: alert?.remote_ip,
  };
  const packetContext = buildPacketInspectionContext(anchor, packets, alerts);
  const peerAlerts = (Array.isArray(alerts) ? alerts : []).filter((row) => {
    const left = packetFlowIdentity(anchor);
    const right = packetFlowIdentity(row);
    return samePeerIdentity(left, right);
  });
  const { sameRemotePackets, sameRemoteAlerts } = buildSameRemoteActivitySample(anchor, packets, alerts);
  const relatedFlows = buildRelatedFlowsSample(anchor, packets);
  const alertCorrelation = buildAlertCorrelationSample(packetContext.related_alerts || [], peerAlerts, sameRemoteAlerts);
  const rootCauseGroups = buildRootCauseGroupsSample({
    processCorrelation: packetContext.process_correlation || {},
    alertCorrelation,
    behaviorLabels: packetContext.behavior_labels || [],
    relatedFlows,
    linkedPacketSummary: linkedPacket || null,
  });

  return {
    ...packetContext,
    alert_id: alert?.id,
    packet_id: alert?.packet_id,
    linked_packet_id: linkedPacket?.id || null,
    linked_packet_summary: linkedPacket || null,
    related_packets: packetContext.related_packets || [],
    related_alerts: peerAlerts.filter((row) => cleanText(row?.id) !== cleanText(alert?.id)).slice(0, 5),
    same_remote_packets: sameRemotePackets,
    same_remote_alerts: sameRemoteAlerts,
    related_flows: relatedFlows,
    alert_correlation: alertCorrelation,
    root_cause_groups: rootCauseGroups,
    source: packetContext.source || "frontend-sample",
  };
}

function buildRisk(packet, guess, payload, context, signals) {
  const reasons = [];
  let score = 0.18;
  const direction = normalizeDirection(packet?.direction || context?.direction);
  const endpoints = determineEndpoints(packet);
  const process = processSummary(packet);
  const behaviorLabels = Array.isArray(context?.behavior_labels) ? context.behavior_labels : Array.isArray(context?.behaviorLabels) ? context.behaviorLabels : [];

  if (isRemoteIp(endpoints.remoteEndpoint)) {
    score += 0.12;
    reasons.push("Remote IP is a public WAN host.");
  }
  if (direction === "INCOMING") {
    score += 0.16;
    reasons.push("Traffic is inbound from a remote host.");
  }
  if (guess.label.includes("IPsec") || guess.label.includes("OpenVPN") || guess.label.includes("WireGuard") || guess.classification.includes("tunnel")) {
    score += 0.18;
    reasons.push("Traffic matches an encrypted tunnel or NAT traversal signature.");
  }
  if (signals.unusualPort && signals.servicePort) {
    score += 0.1;
    reasons.push(`${guess.label} metadata is present on unusual port ${signals.servicePort}.`);
  }
  if (dnsTunnelLike(packet)) {
    score += 0.14;
    reasons.push("DNS query shape looks tunnel-like or unusually long.");
  }
  if (!hasValue(packet?.app_protocol)) {
    score += 0.08;
    reasons.push("Application attribution is still unknown.");
  }
  if (!hasValue(packet?.process_name) && !hasValue(packet?.pid)) {
    score += 0.12;
    reasons.push(process.reasonUnavailable);
  }
  if (payload.binaryLike) {
    score += 0.08;
    reasons.push("Payload preview looks binary or encrypted.");
  }
  if (signals.notes.length) {
    score += Math.min(0.12, signals.notes.length * 0.04);
    reasons.push(...signals.notes);
  }
  const flowAlertsTotal = Number(context?.flow_alerts_total ?? context?.flowAlertsTotal ?? 0);
  if (flowAlertsTotal > 0) {
    score += Math.min(0.18, flowAlertsTotal * 0.06);
    reasons.push(`${flowAlertsTotal} related alert(s) were observed for this flow.`);
  }
  if (behaviorLabels.length) {
    score += Math.min(0.16, behaviorLabels.length * 0.04);
    reasons.push(`Observed behavior pattern(s): ${behaviorLabels.join(", ")}.`);
  }
  score = Math.min(0.98, score);

  let label = "Low";
  let tone = "focus";
  if (score >= 0.78) {
    label = "High";
    tone = "warning";
  } else if (score >= 0.48) {
    label = "Medium";
    tone = "active";
  }

  return {
    score,
    label,
    tone,
    reasons,
    summary:
      reasons[0] ||
      "Packet stands out because it crosses a monitored boundary and still lacks full attribution.",
  };
}

function buildConfidence(packet, guess, payload, signals) {
  let score = 0.28;
  if (hasValue(packet?.direction)) score += 0.12;
  if (hasValue(packet?.app_protocol)) score += 0.24;
  if (guess.confidence) score = Math.max(score, guess.confidence);
  if (hasValue(packet?.l7)) score += 0.12;
  if (hasValue(packet?.tls_version) || hasValue(packet?.http_host) || hasValue(packet?.dns_qname)) score += 0.12;
  if (signals.handshake && signals.handshake !== "No handshake marker captured") score += 0.08;
  if (signals.basis && signals.basis !== "Transport metadata only") score += 0.06;
  if (payload.tabs[0].value !== "No decoded payload available.") score += 0.06;
  score = Math.min(0.98, score);
  let label = "Low";
  if (score >= 0.8) label = "High";
  else if (score >= 0.55) label = "Medium";
  return { score, label };
}

function buildRiskExplanation(packet, risk, confidence, signals, process, context) {
  const suspiciousReasons = (risk.reasons || []).slice(0, 4);
  const benignSignals = [];
  if (hasValue(packet?.process_name) || hasValue(packet?.pid)) benignSignals.push("A local process mapping is available for this packet.");
  if (!signals.unusualPort && signals.servicePort) benignSignals.push(`The observed service uses an expected port (${signals.servicePort}).`);
  if (hasValue(packet?.app_protocol)) benignSignals.push(`Application protocol is identified as ${packet.app_protocol}.`);
  if (hasValue(packet?.tls_version) || hasValue(packet?.http_method) || hasValue(packet?.dns_qname)) benignSignals.push("Protocol decode contains structured evidence, not just a transport hint.");
  if (normalizeDirection(packet?.direction || context?.direction) === "LOCAL") benignSignals.push("Traffic appears local-only rather than remote WAN traffic.");
  const confidenceText =
    confidence.label === "High"
      ? "High confidence because the packet has protocol evidence beyond a simple port hint."
      : confidence.label === "Medium"
        ? "Medium confidence because protocol evidence is present, but some interpretation still relies on heuristics."
        : "Low confidence because interpretation still depends heavily on transport and limited payload context.";
  const narrative = `${risk.label} risk with ${confidence.label.toLowerCase()} confidence. ${suspiciousReasons[0] || "The packet is mainly interesting because it crossed a monitored boundary."} ${process.reasonUnavailable ? `Process attribution gap: ${process.reasonUnavailable}` : process.hint || ""}`.trim();
  return {
    narrative,
    rows: toRows([
      { label: "Top Reasons", value: suspiciousReasons.length ? suspiciousReasons.join(" | ") : "No strong suspicious reasons in the current sample" },
      { label: "Likely Benign Signals", value: benignSignals.length ? benignSignals.join(" | ") : "No strong benign signal in the current sample" },
      { label: "Confidence Text", value: confidenceText },
      { label: "Analyst Narrative", value: narrative },
    ]),
    groups: [
      {
        title: "Top Reasons",
        items: suspiciousReasons.map((reason) => ({ title: reason, body: "This evidence pushes the packet higher in the analyst queue." })),
      },
      {
        title: "Likely Benign Signals",
        items: benignSignals.map((reason) => ({ title: reason, body: "This reduces uncertainty or explains why the flow may be expected." })),
      },
      {
        title: "Confidence",
        items: [{ title: `${confidence.label} confidence`, body: confidenceText }],
      },
    ].filter((group) => group.items.length),
  };
}

function buildFlowContext(packet, context) {
  const conversationKey = cleanText(context?.conversation_key) || buildConversationKey(packet);
  const firstSeen = formatTimestamp(context?.first_seen || context?.firstSeen || packet?.ts);
  const lastSeen = formatTimestamp(context?.last_seen || context?.lastSeen || packet?.ts);
  const durationMs = Math.max(0, Number(context?.duration_ms ?? context?.durationMs ?? 0));
  const flowPacketsTotal = Number(context?.flow_packets_total ?? context?.flowPacketsTotal ?? 0);
  const behaviorLabels = Array.isArray(context?.behavior_labels) ? context.behavior_labels : Array.isArray(context?.behaviorLabels) ? context.behaviorLabels : [];
  let burstLabel = "Isolated in current sample";
  if (flowPacketsTotal >= 6 && durationMs <= 30000) burstLabel = "Burst observed in current sample";
  else if (flowPacketsTotal > 1) burstLabel = "Recurring flow in current sample";
  if (behaviorLabels.includes("Burst pattern observed")) burstLabel = "Burst observed in current sample";
  return {
    flowId: cleanText(context?.flow_id) || "-",
    conversationKey,
    firstSeen,
    lastSeen,
    duration: formatDuration(durationMs),
    burstLabel,
    behaviorSummary: behaviorLabels.length ? behaviorLabels.join(" | ") : "No broader behavior pattern in current sample",
    previousPacketDelta: Number.isFinite(context?.previous_packet_delta_ms) ? formatDuration(context.previous_packet_delta_ms) : Number.isFinite(context?.previousPacketDeltaMs) ? formatDuration(context.previousPacketDeltaMs) : "-",
  };
}

function buildRelatedActivity(context) {
  const relatedPackets = Array.isArray(context?.related_packets) ? context.related_packets : [];
  const relatedAlerts = Array.isArray(context?.related_alerts) ? context.related_alerts : [];
  const sameRemotePackets = Array.isArray(context?.same_remote_packets) ? context.same_remote_packets : Array.isArray(context?.sameRemotePackets) ? context.sameRemotePackets : [];
  const sameRemoteAlerts = Array.isArray(context?.same_remote_alerts) ? context.same_remote_alerts : Array.isArray(context?.sameRemoteAlerts) ? context.sameRemoteAlerts : [];
  const relatedFlows = Array.isArray(context?.related_flows) ? context.related_flows : Array.isArray(context?.relatedFlows) ? context.relatedFlows : [];
  const rootCauseGroups = Array.isArray(context?.root_cause_groups) ? context.root_cause_groups : Array.isArray(context?.rootCauseGroups) ? context.rootCauseGroups : [];
  const linkedPacketSummary = context?.linked_packet_summary || context?.linkedPacketSummary || null;
  const process = context?.process_correlation || context?.processCorrelation || {};
  const sameProcessPackets = Array.isArray(process?.related_packets) ? process.related_packets : Array.isArray(process?.relatedPackets) ? process.relatedPackets : [];
  const sameProcessAlerts = Array.isArray(process?.related_alerts) ? process.related_alerts : Array.isArray(process?.relatedAlerts) ? process.relatedAlerts : [];

  return [
    linkedPacketSummary
      ? {
          title: "Linked Packet",
          items: [
            {
              title: `${cleanText(linkedPacketSummary?.ts) || "-"} | ${cleanText(linkedPacketSummary?.src) || "-"} -> ${cleanText(linkedPacketSummary?.dst) || "-"}`,
              body: `${normalizeProto(linkedPacketSummary?.proto) || "OTHER"} ${cleanText(linkedPacketSummary?.sport) || "-"} -> ${cleanText(linkedPacketSummary?.dport) || "-"} | ${cleanText(linkedPacketSummary?.summary) || "Packet tied to this alert"}`,
            },
          ],
        }
      : null,
    {
      title: "Related Packets",
      items: relatedPackets.map((row) => ({
        title: `${cleanText(row?.ts) || "-"} | ${cleanText(row?.src) || "-"} -> ${cleanText(row?.dst) || "-"}`,
        body: `${normalizeProto(row?.proto) || "OTHER"} ${cleanText(row?.sport) || "-"} -> ${cleanText(row?.dport) || "-"} | ${cleanText(row?.summary) || "Packet in same flow"}`,
      })),
    },
    {
      title: "Related Alerts",
      items: relatedAlerts.map((row) => ({
        title: `${cleanText(row?.ts) || "-"} | ${cleanText(row?.attack_type) || "Alert"}`,
        body: `${sentenceCase(row?.severity || "info")} | ${cleanText(row?.detail) || "Detection linked to this peer/flow"}`,
      })),
    },
    {
      title: "Related Flows",
      items: relatedFlows.map((row) => ({
        title: cleanText(row?.title) || "Related flow",
        body: cleanText(row?.body) || "Flow summary unavailable",
      })),
    },
    {
      title: "Same Remote Host Traffic",
      items: sameRemotePackets.map((row) => ({
        title: `${cleanText(row?.ts) || "-"} | ${cleanText(row?.src) || "-"} -> ${cleanText(row?.dst) || "-"}`,
        body: `${normalizeProto(row?.proto) || "OTHER"} ${cleanText(row?.sport) || "-"} -> ${cleanText(row?.dport) || "-"} | ${cleanText(row?.summary) || "Packet with the same remote host"}`,
      })),
    },
    {
      title: "Same Remote Host Alerts",
      items: sameRemoteAlerts.map((row) => ({
        title: `${cleanText(row?.ts) || "-"} | ${cleanText(row?.attack_type) || "Alert"}`,
        body: `${sentenceCase(row?.severity || "info")} | ${cleanText(row?.detail) || "Alert tied to the same remote host"}`,
      })),
    },
    {
      title: "Same Process Traffic",
      items: sameProcessPackets.map((row) => ({
        title: `${cleanText(row?.ts) || "-"} | ${cleanText(row?.src) || "-"} -> ${cleanText(row?.dst) || "-"}`,
        body: `${normalizeProto(row?.proto) || "OTHER"} ${cleanText(row?.sport) || "-"} -> ${cleanText(row?.dport) || "-"} | ${cleanText(row?.summary) || "Packet from the same process"}`,
      })),
    },
    {
      title: "Same Process Alerts",
      items: sameProcessAlerts.map((row) => ({
        title: `${cleanText(row?.ts) || "-"} | ${cleanText(row?.attack_type) || "Alert"}`,
        body: `${sentenceCase(row?.severity || "info")} | ${cleanText(row?.detail) || "Alert linked to the same process"}`,
      })),
    },
    {
      title: "Root Cause Groups",
      items: rootCauseGroups.map((row) => ({
        title: cleanText(row?.title) || "Root cause group",
        body: cleanText(row?.body) || "Root cause summary unavailable",
      })),
    },
  ].filter((group) => group.items.length);
}

function buildBehaviorGroups(context) {
  const behaviorLabels = Array.isArray(context?.behavior_labels) ? context.behavior_labels : Array.isArray(context?.behaviorLabels) ? context.behaviorLabels : [];
  const process = context?.process_correlation || context?.processCorrelation || {};
  const host = context?.host_correlation || context?.hostCorrelation || {};
  const port = context?.port_correlation || context?.portCorrelation || {};
  const clusters = Array.isArray(context?.conversation_clusters) ? context.conversation_clusters : Array.isArray(context?.conversationClusters) ? context.conversationClusters : [];

  return [
    {
      title: "Process-centric",
      eyebrow: "Behavior lens",
      rows: toRows([
        { label: "Process", value: process?.label || "Unknown process" },
        { label: "Pattern", value: process?.pattern || process?.reason_unavailable || process?.reasonUnavailable },
        { label: "PID", value: process?.pid },
        { label: "Parent PID", value: process?.parent_pid ?? process?.parentPid },
        { label: "Parent Process", value: process?.parent_process_name ?? process?.parentProcessName },
        { label: "Executable Path", value: process?.executable_path ?? process?.executablePath },
        { label: "Attribution Confidence", value: process?.attribution_confidence ?? process?.attributionConfidence },
        { label: "Attribution Source", value: process?.attribution_source ?? process?.attributionSource },
        { label: "Packets Seen", value: formatNumber(Number(process?.packets_total ?? process?.packetsTotal ?? 0)) },
        { label: "Alerts Seen", value: formatNumber(Number(process?.alerts_total ?? process?.alertsTotal ?? 0)) },
        { label: "Sessions", value: formatNumber(Number(process?.sessions_total ?? process?.sessionsTotal ?? 0)) },
        { label: "Ports Touched", value: formatNumber(Number(process?.ports_total ?? process?.portsTotal ?? 0)) },
        { label: "Remote Hosts", value: formatNumber(Number(process?.remote_hosts_total ?? process?.remoteHostsTotal ?? 0)) },
      ]),
      items: Array.isArray(process?.related_packets)
        ? process.related_packets.map((sample) => ({
            title: `${cleanText(sample?.ts) || "-"} | ${cleanText(sample?.src) || "-"} -> ${cleanText(sample?.dst) || "-"}`,
            body: `${normalizeProto(sample?.proto) || "OTHER"} ${cleanText(sample?.sport) || "-"} -> ${cleanText(sample?.dport) || "-"} | ${cleanText(sample?.summary) || "Same-process packet"}`,
          }))
        : Array.isArray(process?.relatedPackets)
          ? process.relatedPackets.map((sample) => ({
              title: `${cleanText(sample?.ts) || "-"} | ${cleanText(sample?.src) || "-"} -> ${cleanText(sample?.dst) || "-"}`,
              body: `${normalizeProto(sample?.proto) || "OTHER"} ${cleanText(sample?.sport) || "-"} -> ${cleanText(sample?.dport) || "-"} | ${cleanText(sample?.summary) || "Same-process packet"}`,
            }))
          : Array.isArray(process?.flow_samples)
            ? process.flow_samples.map((sample) => ({
                title: cleanText(sample?.title) || "Observed session",
                body: cleanText(sample?.body) || "Process activity sample",
              }))
            : Array.isArray(process?.flowSamples)
              ? process.flowSamples.map((sample) => ({
                  title: cleanText(sample?.title) || "Observed session",
                  body: cleanText(sample?.body) || "Process activity sample",
                }))
              : [],
    },
    {
      title: "Host-centric",
      eyebrow: "Behavior lens",
      rows: toRows([
        { label: "Local Host", value: host?.local_ip || host?.localIp },
        { label: "Pattern", value: host?.pattern },
        { label: "Remote Hosts", value: formatNumber(Number(host?.remote_hosts_total ?? host?.remoteHostsTotal ?? 0)) },
        { label: "Sessions", value: formatNumber(Number(host?.sessions_total ?? host?.sessionsTotal ?? 0)) },
        { label: "Remote Ports", value: formatNumber(Number(host?.remote_ports_total ?? host?.remotePortsTotal ?? 0)) },
        { label: "Selected Remote Sessions", value: formatNumber(Number(host?.selected_remote_sessions_total ?? host?.selectedRemoteSessionsTotal ?? 0)) },
        { label: "Burst Window (10s)", value: formatNumber(Number(host?.burst_packets_10s ?? host?.burstPackets10s ?? 0)) },
        { label: "Behavior Labels", value: behaviorLabels.length ? behaviorLabels.join(" | ") : "-" },
      ]),
      items: [],
    },
    {
      title: "Port-centric",
      eyebrow: "Behavior lens",
      rows: toRows([
        { label: "Pattern", value: port?.pattern },
        { label: "Local Port", value: port?.local_port ?? port?.localPort },
        { label: "Remote Port", value: port?.remote_port ?? port?.remotePort },
        { label: "Local Port Sessions", value: formatNumber(Number(port?.local_port_sessions_total ?? port?.localPortSessionsTotal ?? 0)) },
        { label: "Local Port Remote Hosts", value: formatNumber(Number(port?.local_port_remote_hosts_total ?? port?.localPortRemoteHostsTotal ?? 0)) },
        { label: "Remote Port Sessions", value: formatNumber(Number(port?.remote_port_sessions_total ?? port?.remotePortSessionsTotal ?? 0)) },
        { label: "Remote Port Remote Hosts", value: formatNumber(Number(port?.remote_port_remote_hosts_total ?? port?.remotePortRemoteHostsTotal ?? 0)) },
      ]),
      items: [],
    },
    {
      title: "Conversation Clusters",
      eyebrow: "Behavior lens",
      rows: toRows([
        { label: "Clusters Visible", value: formatNumber(clusters.length) },
        { label: "Sample Window", value: `${formatNumber(Number(context?.sample_packets ?? context?.samplePackets ?? 0))} packets / ${formatNumber(Number(context?.sample_alerts ?? context?.sampleAlerts ?? 0))} alerts` },
      ]),
      items: clusters.map((cluster) => ({
        title: cleanText(cluster?.title) || "Conversation cluster",
        body: cleanText(cluster?.body) || "Cluster summary unavailable",
      })),
    },
  ].filter((group) => group.rows.length || group.items.length);
}

function buildRawRows(data, handledKeys) {
  return Object.entries(data || {})
    .filter(([key, value]) => !handledKeys.has(key) && hasValue(Array.isArray(value) ? value.join(", ") : value))
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, value]) => ({ label: key.replaceAll("_", " "), value: Array.isArray(value) ? value.join(", ") : String(value) }));
}

function actionHint(packet, risk, guess, context) {
  const behaviorLabels = Array.isArray(context?.behavior_labels) ? context.behavior_labels : Array.isArray(context?.behaviorLabels) ? context.behaviorLabels : [];
  const payload = analyzePayload(packet);
  const signals = protocolSignals(packet, serviceGuess(packet), payload);
  if (behaviorLabels.some((label) => /fan-out|sweep|burst/i.test(label))) {
    return "Pivot into the broader host pattern to confirm whether this flow belongs to scanning, burst, or wide fan-out behavior.";
  }
  if (risk.label === "High") {
    return "Escalate into related packets and confirm whether the remote peer and service are expected for this host.";
  }
  if (signals.unusualPort) {
    return "Confirm whether the destination service is expected on this non-standard port before dismissing it as benign.";
  }
  if (guess.label.includes("IPsec") || guess.label.includes("WireGuard") || guess.label.includes("OpenVPN")) {
    return "Verify whether this host is expected to terminate VPN or IPsec traffic before treating it as malicious.";
  }
  if (Number(context?.flow_alerts_total ?? context?.flowAlertsTotal ?? 0) > 0) {
    return "Review the linked alerts and same-peer packets to confirm whether this packet belongs to a noisy or suspicious burst.";
  }
  return "Correlate with adjacent packets and host attribution before escalating.";
}

function formatRemoteLocation(packet) {
  const parts = [
    cleanText(packet?.remote_ip),
    cleanText(packet?.city),
    cleanText(packet?.country_name || packet?.country),
    cleanText(packet?.asn),
  ].filter(Boolean);
  return parts.join(" | ") || "-";
}

function formatRemoteLocationLabel(packet) {
  const parts = [
    cleanText(packet?.remote_ip),
    cleanText(packet?.city),
    cleanText(packet?.country_name || packet?.country),
    cleanText(packet?.asn),
    cleanText(packet?.org),
  ].filter(Boolean);
  return parts.join(" | ") || "-";
}

export function buildPacketInspectionModel(packet, options = {}) {
  if (!packet) return { empty: true, analystCards: [] };

  const context = options.context || {};
  const capture = options.capture || {};
  const payload = analyzePayload(packet);
  const guess = serviceGuess(packet);
  const signals = protocolSignals(packet, guess, payload);
  const classification = sentenceCase(packetClassification(packet, guess, payload, signals));
  const confidence = buildConfidence(packet, guess, payload, signals);
  const risk = buildRisk(packet, guess, payload, context, signals);
  const process = processSummary(packet);
  const flow = getFlowSummary(packet.src, packet.dst);
  const endpoints = determineEndpoints(packet);
  const flowContext = buildFlowContext(packet, context);
  const ports = resolveConversationPorts(packet, endpoints);
  const behaviorLabels = Array.isArray(context?.behavior_labels) ? context.behavior_labels : Array.isArray(context?.behaviorLabels) ? context.behaviorLabels : [];
  const riskExplanation = buildRiskExplanation(packet, risk, confidence, signals, process, context);
  const alertCorrelation = context?.alert_correlation || context?.alertCorrelation || {};
  const packetDirection = packet?.direction || context?.direction;
  const headline = `${formatDirection(packetDirection)} ${normalizeProto(packet?.proto) || "traffic"} ${ports.remotePort || ports.localPort || ""} traffic`.trim();
  const interpretedSummary = `${sentenceCase(cleanText(packetDirection) || "Unknown")} ${normalizeProto(packet?.proto) || "traffic"} ${cleanText(packet?.dport) || cleanText(packet?.sport) || ""}`.trim();

  const analystCards = [
    {
      label: "Protocol Guess",
      value: guess.label,
      hint: `${classification} | ${signals.basis}`,
      tone: "active",
    },
    {
      label: "Risk",
      value: `${risk.label} (${formatPercent(risk.score)})`,
      hint: risk.summary,
      tone: risk.tone,
    },
    {
      label: "Flow / Conversation",
      value: flowContext.conversationKey,
      hint: `${flow.label} | ${flowContext.behaviorSummary}`,
      tone: "focus",
    },
    {
      label: "Process Attribution",
      value: process.label,
      hint: process.reasonUnavailable || process.hint,
      tone: cleanText(packet?.process_name) || cleanText(packet?.pid) ? "active" : "warning",
    },
    {
      label: "Why It Matters",
      value: actionHint(packet, risk, guess, context),
      hint: formatRemoteLocationLabel(packet),
      tone: "neutral",
    },
  ];

  const applicationGroups = [
    {
      title: "DNS",
      rows: toRows([
        { label: "Query Name", value: packet?.dns_qname },
        { label: "Query Type", value: packet?.dns_qtype },
        { label: "Response Code", value: packet?.dns_rcode },
        { label: "Tunnel-like Shape", value: dnsTunnelLike(packet) ? "Yes" : "No" },
      ]),
    },
    {
      title: "HTTP",
      rows: toRows([
        { label: "Method", value: packet?.http_method },
        { label: "Status", value: packet?.http_status },
        { label: "Reason", value: packet?.http_reason },
        { label: "Host", value: packet?.http_host },
        { label: "Path", value: packet?.http_path },
        { label: "User Agent", value: packet?.http_user_agent },
        { label: "Content Type", value: packet?.http_content_type },
      ]),
    },
    {
      title: "TLS",
      rows: toRows([
        { label: "Version", value: packet?.tls_version },
        { label: "SNI", value: packet?.tls_sni || packet?.sni },
        { label: "ALPN", value: formatList(packet?.tls_alpn || packet?.alpn) },
        { label: "JA3", value: packet?.ja3 },
        { label: "JA3 String", value: packet?.ja3_str },
        { label: "JA4", value: packet?.ja4 },
      ]),
    },
  ].filter((group) => group.rows.length);

  const handledKeys = new Set([
    "src",
    "dst",
    "remote_ip",
    "direction",
    "scope",
    "inside_outside",
    "summary",
    "proto",
    "sport",
    "dport",
    "length",
    "ttl",
    "flags",
    "app_protocol",
    "app_category",
    "app_confidence",
    "process_name",
    "pid",
    "parent_pid",
    "parent_process_name",
    "executable_path",
    "attribution_confidence",
    "attribution_reason_unavailable",
    "attribution_source",
    "src_mac",
    "dst_mac",
    "vendor_src",
    "vendor_dst",
    "country",
    "country_code",
    "country_name",
    "city",
    "org",
    "isp",
    "route",
    "asn",
    "dns_qname",
    "dns_qtype",
    "dns_rcode",
    "http_method",
    "http_status",
    "http_reason",
    "http_host",
    "http_path",
    "http_user_agent",
    "http_content_type",
    "tls_version",
    "tls_sni",
    "tls_alpn",
    "sni",
    "alpn",
    "ja3",
    "ja3_str",
    "ja4",
    "protocol_basis",
    "protocol_notes",
    "protocol_handshake",
    "protocol_unusual_port",
    "payload_hex",
    "payload_ascii",
    "payload_len",
    "payload_binary_like",
    "payload_entropy",
    "payload_printable_ratio",
    "l7",
    "attack_type",
    "score",
    "score_raw",
    "engine",
    "detail",
    "incident_id",
    "incident_count",
    "incident_score",
    "timestamp",
  ]);

  return {
    empty: false,
    tone: risk.tone,
    headline: headline || `${interpretedSummary || "Packet"} traffic`,
    summaryText: `Likely ${guess.label}; ${classification.toLowerCase()}. ${signals.notesText || signals.handshake || ""}`.trim(),
    interpretedSummary: `${guess.label} | ${classification}`,
    analystCards,
    investigationTabs: [
      { id: "packet", label: "Packet", sections: ["hero", "verdict", "network", "transport", "risk", "application", "payload", "enrichment", "raw"] },
      { id: "flow", label: "Flow", sections: ["hero", "flow", "correlation", "related", "risk"] },
      { id: "process", label: "Process", sections: ["hero", "process", "correlation", "related", "risk"] },
    ],
    verdictRows: [
      { label: "Packet Type", value: classification },
      { label: "Protocol Guess", value: `${guess.label} (${formatPercent(guess.confidence || confidence.score)})` },
      { label: "Risk Level", value: `${risk.label} (${formatPercent(risk.score)})` },
      { label: "Confidence", value: `${confidence.label} (${formatPercent(confidence.score)})` },
      { label: "Handshake Check", value: signals.handshake },
      { label: "Behavior Pattern", value: behaviorLabels.length ? behaviorLabels.join(" | ") : "No broader behavior pattern in current sample" },
      { label: "Why Interesting", value: risk.reasons.join(" ") || "Cross-boundary packet with incomplete attribution." },
    ],
    networkRows: [
      { label: "Source -> Destination", value: `${cleanText(packet?.src) || "-"} -> ${cleanText(packet?.dst) || "-"}` },
      { label: "Direction", value: formatDirection(packet?.direction) },
      { label: "Remote Endpoint", value: endpoints.remoteEndpoint },
      { label: "Local Endpoint", value: endpoints.localEndpoint },
      { label: "Remote Zone", value: endpoints.remoteZone },
      { label: "Local Zone", value: endpoints.localZone },
      { label: "Peer Side", value: endpoints.peer.side.label },
      { label: "Flow", value: flow.label },
      { label: "Interface", value: capture.iface || "-" },
      { label: "Interface Alias", value: capture.interfaceAlias || "-" },
      { label: "Capture Source", value: capture.source || "-" },
      { label: "Capture Engine", value: capture.engine || "-" },
      { label: "TTL", value: packet?.ttl },
      { label: "Length", value: packet?.length ? `${packet.length} bytes` : "-" },
      { label: "Timestamp", value: packet?.ts || packet?.timestamp },
      { label: "Previous Packet Gap", value: flowContext.previousPacketDelta },
    ],
    transportRows: [
      { label: "Transport", value: normalizeProto(packet?.proto) || "-" },
      { label: "Source Port", value: packet?.sport },
      { label: "Destination Port", value: packet?.dport },
      { label: "Service Guess", value: `${guess.label} | ${signals.basis}` },
      { label: "Handshake Check", value: signals.handshake },
      { label: "Unusual Port", value: signals.unusualPortLabel },
      { label: "Binary / Encrypted", value: signals.encryptedLabel },
      { label: "Protocol Notes", value: signals.notesText },
      { label: "Classification", value: classification },
      { label: "Flags", value: packet?.flags },
      { label: "App Protocol", value: packet?.app_protocol },
      { label: "App Category", value: packet?.app_category },
      { label: "App Confidence", value: hasValue(packet?.app_confidence) ? formatSignalScore(packet.app_confidence) : "-" },
      { label: "Raw Summary", value: packet?.summary },
      { label: "Decoded Layer", value: packet?.l7 },
    ],
    processRows: [
      { label: "Process", value: process.label },
      { label: "PID", value: packet?.pid },
      { label: "Parent PID", value: packet?.parent_pid },
      { label: "Parent Process", value: packet?.parent_process_name },
      { label: "Executable Path", value: packet?.executable_path },
      { label: "Attribution Confidence", value: process.confidenceLabel },
      { label: "Attribution Source", value: packet?.attribution_source },
      { label: "Reason Unavailable", value: process.reasonUnavailable || process.hint },
      { label: "Source MAC", value: packet?.src_mac },
      { label: "Source Vendor", value: packet?.vendor_src },
      { label: "Destination MAC", value: packet?.dst_mac },
      { label: "Destination Vendor", value: packet?.vendor_dst },
    ],
    flowRows: [
      { label: "Flow ID", value: flowContext.flowId },
      { label: "Conversation Key", value: flowContext.conversationKey },
      { label: "Packets In Flow", value: formatNumber(Number(context?.flow_packets_total ?? context?.flowPacketsTotal ?? 1)) },
      { label: "Related Alerts", value: formatNumber(Number(context?.flow_alerts_total ?? context?.flowAlertsTotal ?? 0)) },
      { label: "Peer Alerts", value: formatNumber(Number(alertCorrelation?.peer_alerts_total ?? alertCorrelation?.peerAlertsTotal ?? 0)) },
      { label: "Same Remote Alerts", value: formatNumber(Number(alertCorrelation?.same_remote_alerts_total ?? alertCorrelation?.sameRemoteAlertsTotal ?? 0)) },
      { label: "Attack Types", value: Array.isArray(alertCorrelation?.attack_types) ? alertCorrelation.attack_types.join(" | ") : Array.isArray(alertCorrelation?.attackTypes) ? alertCorrelation.attackTypes.join(" | ") : "-" },
      { label: "Engines", value: Array.isArray(alertCorrelation?.engines) ? alertCorrelation.engines.join(" | ") : "-" },
      { label: "Bytes In", value: `${formatNumber(Number(context?.flow_bytes_in ?? 0))} bytes` },
      { label: "Bytes Out", value: `${formatNumber(Number(context?.flow_bytes_out ?? 0))} bytes` },
      { label: "Same Peer Packets", value: formatNumber(Number(context?.same_peer_packets_total ?? context?.peerPacketsTotal ?? 0)) },
      { label: "Same Peer Alerts", value: formatNumber(Number(context?.same_peer_alerts_total ?? context?.peerAlertsTotal ?? 0)) },
      { label: "Same Port Context", value: formatNumber(Number(context?.same_port_packets_total ?? context?.samePortCount ?? 0)) },
      { label: "Behavior Labels", value: flowContext.behaviorSummary },
      { label: "First Seen", value: flowContext.firstSeen },
      { label: "Last Seen", value: flowContext.lastSeen },
      { label: "Duration", value: flowContext.duration },
      { label: "Burst Assessment", value: flowContext.burstLabel },
      { label: "Sample Window", value: `${formatNumber(Number(context?.sample_packets ?? context?.samplePackets ?? 0))} packets / ${formatNumber(Number(context?.sample_alerts ?? context?.sampleAlerts ?? 0))} alerts` },
    ],
    enrichmentRows: [
      { label: "Country", value: packet?.country_name || packet?.country },
      { label: "City", value: packet?.city },
      { label: "ASN", value: packet?.asn },
      { label: "Organization", value: packet?.org },
      { label: "ISP", value: packet?.isp },
      { label: "Route", value: packet?.route },
      { label: "Scope", value: packet?.scope },
    ],
    applicationGroups,
    payload,
    payloadRows: [
      { label: "Payload Length", value: packet?.payload_len ? `${packet.payload_len} bytes` : "0 bytes" },
      { label: "Printable Ratio", value: payload.tabs[1].value.startsWith("No ") && readNumber(packet?.payload_printable_ratio) == null ? "-" : formatPercent(payload.printableRatio) },
      { label: "Entropy", value: readNumber(payload.entropy) != null ? payload.entropy.toFixed(2) : "-" },
      { label: "Entropy Hint", value: payload.entropyHint },
      { label: "Binary / Encrypted Guess", value: payload.binaryLike ? "Likely binary or encrypted" : "Mostly printable preview" },
    ],
    correlationGroups: buildBehaviorGroups(context),
    relatedGroups: buildRelatedActivity(context),
    riskExplanation,
    rawRows: buildRawRows(packet, handledKeys),
  };
}

export function buildAlertInspectionModel(alert, options = {}) {
  if (!alert) return { empty: true, analystCards: [] };

  const context = options.context || {};
  const remote = getPeerInfo(alert);
  const payload = analyzePayload(alert);
  const guess = serviceGuess(alert);
  const signals = protocolSignals(alert, guess, payload);
  const severity = sentenceCase(alert?.severity || "Info");
  const score = Number(alert?.score || alert?.score_raw || 0);
  const tone = score >= 0.75 ? "warning" : score >= 0.45 ? "active" : "focus";
  const processCorrelation = context?.process_correlation || context?.processCorrelation || {};
  const alertCorrelation = context?.alert_correlation || context?.alertCorrelation || {};
  const flowContext = buildFlowContext(alert, context);
  const riskExplanation = {
    narrative: `${severity} alert tied to ${guess.label || normalizeProto(alert?.proto)} traffic. ${cleanText(alert?.detail) || "Review linked packet, flow, and process context."}`.trim(),
    rows: toRows([
      { label: "Top Reasons", value: cleanText(alert?.detail) || "Detector evidence is attached to this alert." },
      { label: "Likely Benign Signals", value: signals.unusualPort ? "-" : `Protocol evidence points to ${guess.label} on an expected port.` },
      { label: "Confidence Text", value: signals.handshake && signals.handshake !== "No handshake marker captured" ? `Confidence is strengthened by ${signals.handshake}.` : "Confidence comes mainly from detector output and surrounding flow correlation." },
      { label: "Analyst Narrative", value: `${severity} alert with ${cleanText(alert?.engine) || "detector"} evidence. ${cleanText(alert?.detail) || ""}`.trim() },
    ]),
    groups: [
      {
        title: "Top Reasons",
        items: [{ title: cleanText(alert?.detail) || "Detector evidence present", body: `Engine: ${cleanText(alert?.engine) || "-"}` }],
      },
      {
        title: "Confidence",
        items: [{ title: `${severity} severity`, body: signals.handshake && signals.handshake !== "No handshake marker captured" ? `Protocol evidence includes ${signals.handshake}.` : "Use linked packet and flow context to confirm the alert." }],
      },
    ],
  };
  const analystCards = [
    {
      label: "Detection",
      value: cleanText(alert?.attack_type) || "Alert",
      hint: cleanText(alert?.detail) || "Detection detail available below.",
      tone: "warning",
    },
    {
      label: "Severity",
      value: `${severity} (${formatSignalScore(score)})`,
      hint: `Engine: ${cleanText(alert?.engine) || "-"}`,
      tone,
    },
    {
      label: "Remote Peer",
      value: remote.ip || cleanText(alert?.remote_ip) || "-",
      hint: `${normalizeProto(alert?.proto) || "UNKNOWN"} flow`,
      tone: "focus",
    },
    {
      label: "Linked Packet",
      value: cleanText(context?.linked_packet_id || context?.linkedPacketId || alert?.packet_id) || "No linked packet id",
      hint: cleanText(alert?.incident_id) ? `Incident ${alert.incident_id}` : cleanText(processCorrelation?.label) || "No incident correlation yet",
      tone: "active",
    },
    {
      label: "Why It Matters",
      value: cleanText(alert?.detail) || "Review the detection evidence and linked peer history.",
      hint: cleanText((context?.root_cause_groups || context?.rootCauseGroups || [])[0]?.title) || `Related count: ${formatNumber(Number(alert?.incident_count || 1))}`,
      tone: "neutral",
    },
  ];

  const handledKeys = new Set([
    "attack_type",
    "severity",
    "score",
    "score_raw",
    "detail",
    "engine",
    "src",
    "dst",
    "proto",
    "sport",
    "dport",
    "direction",
    "packet_id",
    "incident_id",
    "incident_count",
    "incident_score",
    "remote_ip",
    "app_protocol",
    "app_category",
    "app_confidence",
    "protocol_basis",
    "protocol_notes",
    "protocol_handshake",
    "protocol_unusual_port",
    "pid",
    "process_name",
    "parent_pid",
    "parent_process_name",
    "executable_path",
    "attribution_confidence",
    "attribution_reason_unavailable",
    "attribution_source",
    "dns_qname",
    "dns_qtype",
    "dns_rcode",
    "http_method",
    "http_host",
    "http_path",
    "http_status",
    "http_reason",
    "http_user_agent",
    "http_content_type",
    "sni",
    "tls_version",
    "tls_alpn",
    "ja3",
    "ja3_str",
    "ja4",
    "payload_binary_like",
    "payload_len",
    "payload_hex",
    "payload_ascii",
    "payload_entropy",
    "payload_printable_ratio",
    "ts",
  ]);

  return {
    empty: false,
    tone,
    headline: cleanText(alert?.attack_type) || "Alert detail",
    summaryText: `${guess.label} evidence on ${normalizeProto(alert?.proto) || "UNKNOWN"} ${cleanText(alert?.sport) || "-"} -> ${cleanText(alert?.dport) || "-"}. ${cleanText(alert?.detail) || "Review the linked packet and surrounding flow."}`.trim(),
    interpretedSummary: cleanText(alert?.detail) || "Detection metadata",
    analystCards,
    investigationTabs: [
      { id: "alert", label: "Alert", sections: ["hero", "verdict", "network", "transport", "process", "flow", "application", "payload", "risk", "raw"] },
      { id: "flow", label: "Flow", sections: ["hero", "flow", "correlation", "related", "risk"] },
      { id: "process", label: "Process", sections: ["hero", "process", "correlation", "related", "risk"] },
    ],
    verdictRows: [
      { label: "Severity", value: severity },
      { label: "Score", value: formatSignalScore(score) },
      { label: "Engine", value: alert?.engine },
      { label: "Protocol Guess", value: `${guess.label} (${formatPercent(guess.confidence || confidenceFromSignal(alert?.app_confidence, 0.64))})` },
      { label: "Handshake Check", value: signals.handshake },
      { label: "Why Interesting", value: cleanText(alert?.detail) || "Detection evidence is attached to this alert." },
    ],
    networkRows: [
      { label: "Source -> Destination", value: `${cleanText(alert?.src) || "-"} -> ${cleanText(alert?.dst) || "-"}` },
      { label: "Direction", value: formatDirection(alert?.direction || context?.direction) },
      { label: "Protocol", value: normalizeProto(alert?.proto) || "-" },
      { label: "Source Port", value: alert?.sport },
      { label: "Destination Port", value: alert?.dport },
      { label: "Remote IP", value: cleanText(alert?.remote_ip) || remote.ip || "-" },
      { label: "Linked Packet", value: cleanText(context?.linked_packet_id || context?.linkedPacketId || alert?.packet_id) || "-" },
      { label: "Conversation Key", value: context?.conversation_key || context?.conversationKey },
      { label: "Timestamp", value: alert?.ts },
    ],
    transportRows: [
      { label: "App Protocol", value: alert?.app_protocol },
      { label: "App Category", value: alert?.app_category },
      { label: "App Confidence", value: hasValue(alert?.app_confidence) ? formatSignalScore(alert.app_confidence) : "-" },
      { label: "Service Guess", value: `${guess.label} | ${signals.basis}` },
      { label: "Handshake Check", value: signals.handshake },
      { label: "Unusual Port", value: signals.unusualPortLabel },
      { label: "Binary / Encrypted", value: signals.encryptedLabel },
      { label: "Protocol Notes", value: signals.notesText },
      { label: "Incident Score", value: hasValue(alert?.incident_score) ? formatSignalScore(alert.incident_score) : "-" },
    ],
    processRows: [
      { label: "Process", value: alert?.process_name || processCorrelation?.label },
      { label: "PID", value: alert?.pid || processCorrelation?.pid },
      { label: "Parent PID", value: alert?.parent_pid || processCorrelation?.parent_pid || processCorrelation?.parentPid },
      { label: "Parent Process", value: alert?.parent_process_name || processCorrelation?.parent_process_name || processCorrelation?.parentProcessName },
      { label: "Executable Path", value: alert?.executable_path || processCorrelation?.executable_path || processCorrelation?.executablePath },
      { label: "Attribution Confidence", value: alert?.attribution_confidence || processCorrelation?.attribution_confidence || processCorrelation?.attributionConfidence },
      { label: "Attribution Source", value: alert?.attribution_source || processCorrelation?.attribution_source || processCorrelation?.attributionSource },
      { label: "Reason Unavailable", value: alert?.attribution_reason_unavailable || processCorrelation?.reason_unavailable || processCorrelation?.reasonUnavailable },
      { label: "Linked Packet ID", value: alert?.packet_id },
      { label: "Incident ID", value: alert?.incident_id },
      { label: "Incident Count", value: alert?.incident_count },
    ],
    flowRows: [
      { label: "Flow ID", value: context?.flow_id || context?.flowId },
      { label: "Conversation Key", value: flowContext.conversationKey },
      { label: "Packets In Flow", value: formatNumber(Number(context?.flow_packets_total ?? context?.flowPacketsTotal ?? 0)) },
      { label: "Related Alerts", value: formatNumber(Number(context?.flow_alerts_total ?? context?.flowAlertsTotal ?? 0)) },
      { label: "Peer Alerts", value: formatNumber(Number(alertCorrelation?.peer_alerts_total ?? alertCorrelation?.peerAlertsTotal ?? 0)) },
      { label: "Same Remote Alerts", value: formatNumber(Number(alertCorrelation?.same_remote_alerts_total ?? alertCorrelation?.sameRemoteAlertsTotal ?? 0)) },
      { label: "Attack Types", value: Array.isArray(alertCorrelation?.attack_types) ? alertCorrelation.attack_types.join(" | ") : Array.isArray(alertCorrelation?.attackTypes) ? alertCorrelation.attackTypes.join(" | ") : "-" },
      { label: "Engines", value: Array.isArray(alertCorrelation?.engines) ? alertCorrelation.engines.join(" | ") : "-" },
      { label: "Related Flow Clusters", value: formatNumber(Array.isArray(context?.related_flows) ? context.related_flows.length : Array.isArray(context?.relatedFlows) ? context.relatedFlows.length : 0) },
      { label: "Same Remote Packets", value: formatNumber(Array.isArray(context?.same_remote_packets) ? context.same_remote_packets.length : Array.isArray(context?.sameRemotePackets) ? context.sameRemotePackets.length : 0) },
      { label: "First Seen", value: flowContext.firstSeen },
      { label: "Last Seen", value: flowContext.lastSeen },
      { label: "Duration", value: flowContext.duration },
      { label: "DNS Name", value: alert?.dns_qname },
      { label: "DNS Query Type", value: alert?.dns_qtype },
      { label: "DNS Rcode", value: alert?.dns_rcode },
      { label: "HTTP Host", value: alert?.http_host },
      { label: "HTTP Method", value: alert?.http_method },
      { label: "HTTP Path", value: alert?.http_path },
      { label: "HTTP Status", value: alert?.http_status },
      { label: "HTTP Reason", value: alert?.http_reason },
      { label: "TLS Version", value: alert?.tls_version },
      { label: "ALPN", value: formatList(alert?.tls_alpn || alert?.alpn) },
      { label: "JA3", value: alert?.ja3 },
      { label: "JA4", value: alert?.ja4 },
      { label: "SNI", value: alert?.sni },
    ],
    enrichmentRows: [],
    applicationGroups: [
      {
        title: "TLS / HTTP / DNS",
        rows: toRows([
          { label: "DNS Name", value: alert?.dns_qname },
          { label: "DNS Query Type", value: alert?.dns_qtype },
          { label: "DNS Rcode", value: alert?.dns_rcode },
          { label: "HTTP Method", value: alert?.http_method },
          { label: "HTTP Host", value: alert?.http_host },
          { label: "HTTP Path", value: alert?.http_path },
          { label: "HTTP Status", value: alert?.http_status },
          { label: "HTTP Reason", value: alert?.http_reason },
          { label: "TLS Version", value: alert?.tls_version },
          { label: "SNI", value: alert?.sni },
          { label: "ALPN", value: formatList(alert?.tls_alpn || alert?.alpn) },
          { label: "JA3", value: alert?.ja3 },
          { label: "JA4", value: alert?.ja4 },
          { label: "HTTP User Agent", value: alert?.http_user_agent },
          { label: "Content Type", value: alert?.http_content_type },
        ]),
      },
    ].filter((group) => group.rows.length),
    payload,
    payloadRows: [
      { label: "Payload Length", value: alert?.payload_len ? `${alert.payload_len} bytes` : "0 bytes" },
      { label: "Printable Ratio", value: payload.tabs[1].value.startsWith("No ") && readNumber(alert?.payload_printable_ratio) == null ? "-" : formatPercent(payload.printableRatio) },
      { label: "Entropy", value: readNumber(payload.entropy) != null ? payload.entropy.toFixed(2) : "-" },
      { label: "Entropy Hint", value: payload.entropyHint },
      { label: "Binary / Encrypted Guess", value: payload.binaryLike ? "Likely binary or encrypted" : "Mostly printable preview" },
    ],
    correlationGroups: buildBehaviorGroups(context),
    relatedGroups: buildRelatedActivity(context),
    riskExplanation,
    rawRows: buildRawRows(alert, handledKeys),
  };
}
