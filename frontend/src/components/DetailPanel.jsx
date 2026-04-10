import { getFlowSummary, getPeerInfo } from "../lib/networkView";

const GROUPS = [
  {
    title: "Identity",
    keys: ["src", "dst", "peer_ip", "peer_side", "remote_ip", "direction", "scope", "inside_outside", "flow", "summary"],
  },
  {
    title: "Transport",
    keys: ["proto", "sport", "dport", "length", "ttl", "flags", "packet_id"],
  },
  {
    title: "Geo",
    keys: ["country", "country_code", "country_name", "city", "org", "isp", "route", "asn"],
  },
  {
    title: "Process",
    keys: ["process_name", "pid"],
  },
  {
    title: "Application",
    keys: ["dns_qname", "dns_qtype", "http_method", "http_host", "http_path", "http_user_agent", "tls_version", "tls_sni", "tls_alpn", "ja3", "ja4"],
  },
  {
    title: "Alert",
    keys: ["attack_type", "severity", "score", "score_raw", "engine", "detail", "incident_id", "incident_count", "incident_score"],
  },
];

function formatLabel(key) {
  return key.replaceAll("_", " ");
}

function buildGroups(data) {
  const remaining = new Map(Object.entries(data));
  const sections = [];

  for (const group of GROUPS) {
    const entries = [];
    for (const key of group.keys) {
      if (!remaining.has(key)) continue;
      entries.push([key, remaining.get(key)]);
      remaining.delete(key);
    }
    if (entries.length) {
      sections.push({ title: group.title, entries });
    }
  }

  if (remaining.size) {
    sections.push({
      title: "Other",
      entries: [...remaining.entries()].sort(([left], [right]) => left.localeCompare(right)),
    });
  }
  return sections;
}

function normalizeData(data) {
  if (!data) return data;
  const peer = getPeerInfo(data);
  const flow = getFlowSummary(data.src, data.dst);
  return {
    ...data,
    peer_ip: peer.ip,
    peer_side: peer.side.label,
    flow: flow.label,
  };
}

export function DetailPanel({ title, data }) {
  const normalizedData = normalizeData(data);
  return (
    <div className="mini-panel detail-panel">
      <p className="eyebrow">{title}</p>
      {!normalizedData ? <p className="muted">Select a row to inspect details</p> : null}
      {normalizedData ? (
        <div className="detail-sections">
          {buildGroups(normalizedData).map((group) => (
            <section key={group.title} className="detail-group">
              <h3>{group.title}</h3>
              <dl className="detail-grid">
                {group.entries.map(([key, value]) => (
                  <div key={key}>
                    <dt>{formatLabel(key)}</dt>
                    <dd>{String(value ?? "-")}</dd>
                  </div>
                ))}
              </dl>
            </section>
          ))}
        </div>
      ) : null}
    </div>
  );
}
