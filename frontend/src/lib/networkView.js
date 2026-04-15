function normalizeIp(value) {
  return String(value || "").trim().split("%", 1)[0];
}

function parseIpv4(text) {
  const parts = normalizeIp(text).split(".");
  if (parts.length !== 4) return null;
  const bytes = [];
  for (const part of parts) {
    if (!/^\d+$/.test(part)) return null;
    const num = Number(part);
    if (!Number.isInteger(num) || num < 0 || num > 255) return null;
    bytes.push(num);
  }
  return bytes;
}

function isIpv6(text) {
  const value = normalizeIp(text);
  return value.includes(":");
}

function isIpv6Local(text) {
  const value = normalizeIp(text).toLowerCase();
  if (!value) return false;
  return (
    value === "::1" ||
    value === "::" ||
    value.startsWith("fe80:") ||
    value.startsWith("fc") ||
    value.startsWith("fd") ||
    value.startsWith("ff") ||
    value.startsWith("2001:db8:")
  );
}

export function isLocalIp(ip) {
  const value = normalizeIp(ip);
  if (!value) return false;
  if (isIpv6(value)) return isIpv6Local(value);

  const octets = parseIpv4(value);
  if (!octets) return false;
  const [a, b, c] = octets;

  if (a === 0) return true;
  if (a === 10) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  if (a === 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 192 && b === 168) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 0 && c === 0) return true;
  if (a === 198 && (b === 18 || b === 19)) return true;
  if (a === 192 && b === 0 && octets[2] === 2) return true;
  if (a === 198 && b === 51 && octets[2] === 100) return true;
  if (a === 203 && b === 0 && octets[2] === 113) return true;
  if (a >= 224) return true;
  return false;
}

export function isPrivateIp(ip) {
  const value = normalizeIp(ip);
  return Boolean(value) && isLocalIp(value);
}

export function isPublicIp(ip) {
  const value = normalizeIp(ip);
  return Boolean(value) && !isLocalIp(value);
}

export function isRemoteIp(ip) {
  return isPublicIp(ip);
}

function preferredRemoteIp(...candidates) {
  for (const candidate of candidates) {
    if (isRemoteIp(candidate)) {
      return normalizeIp(candidate);
    }
  }
  for (const candidate of candidates) {
    const value = normalizeIp(candidate);
    if (value) return value;
  }
  return "";
}

export function getTrafficSide(ip) {
  const text = normalizeIp(ip);
  if (!text) return { label: "-", tone: "unknown" };
  if (isLocalIp(text)) return { label: "LAN", tone: "local" };
  if (isRemoteIp(text)) return { label: "WAN", tone: "remote" };
  return { label: "Peer", tone: "unknown" };
}

export function getFlowSummary(src, dst) {
  const srcSide = getTrafficSide(src);
  const dstSide = getTrafficSide(dst);
  return {
    srcSide,
    dstSide,
    label: `${srcSide.label} -> ${dstSide.label}`,
  };
}

export function getPeerInfo(item) {
  const src = normalizeIp(item?.src);
  const dst = normalizeIp(item?.dst);
  const remoteIp = normalizeIp(item?.remote_ip);
  const direction = String(item?.direction || "").trim().toUpperCase();
  const orderedCandidates =
    direction === "INCOMING"
      ? [remoteIp, src, dst]
      : direction === "OUTGOING"
        ? [remoteIp, dst, src]
        : [remoteIp, dst, src];
  const bestPeer = preferredRemoteIp(...orderedCandidates);

  if (bestPeer) {
    const role = bestPeer === src ? "src" : bestPeer === dst ? "dst" : bestPeer === remoteIp && remoteIp === src ? "src" : bestPeer === remoteIp && remoteIp === dst ? "dst" : "either";
    return {
      ip: bestPeer,
      role,
      side: getTrafficSide(bestPeer),
      label: isRemoteIp(bestPeer) ? "Remote" : "Peer",
    };
  }

  return {
    ip: "-",
    role: "either",
    side: { label: "-", tone: "unknown" },
    label: "Peer",
  };
}
