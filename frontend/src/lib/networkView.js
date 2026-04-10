export function isPrivateIp(ip) {
  const text = String(ip || "").trim();
  return (
    text.startsWith("10.") ||
    text.startsWith("192.168.") ||
    text.startsWith("127.") ||
    text.startsWith("169.254.") ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(text)
  );
}

export function getTrafficSide(ip) {
  const text = String(ip || "").trim();
  if (!text) return { label: "-", tone: "unknown" };
  if (isPrivateIp(text)) return { label: "LAN", tone: "local" };
  return { label: "WAN", tone: "remote" };
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
  const src = String(item?.src || "").trim();
  const dst = String(item?.dst || "").trim();
  const remoteIp = String(item?.remote_ip || "").trim();

  if (remoteIp) {
    const role = remoteIp === src ? "src" : remoteIp === dst ? "dst" : "either";
    return {
      ip: remoteIp,
      role,
      side: getTrafficSide(remoteIp),
      label: "Remote",
    };
  }

  if (src && dst) {
    const srcPrivate = isPrivateIp(src);
    const dstPrivate = isPrivateIp(dst);
    if (srcPrivate && !dstPrivate) {
      return {
        ip: dst,
        role: "dst",
        side: getTrafficSide(dst),
        label: "Remote",
      };
    }
    if (dstPrivate && !srcPrivate) {
      return {
        ip: src,
        role: "src",
        side: getTrafficSide(src),
        label: "Remote",
      };
    }
  }

  if (dst) {
    return {
      ip: dst,
      role: "dst",
      side: getTrafficSide(dst),
      label: "Peer",
    };
  }
  if (src) {
    return {
      ip: src,
      role: "src",
      side: getTrafficSide(src),
      label: "Peer",
    };
  }
  return {
    ip: "-",
    role: "either",
    side: { label: "-", tone: "unknown" },
    label: "Peer",
  };
}
