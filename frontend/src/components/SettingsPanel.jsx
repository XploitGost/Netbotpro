export function SettingsPanel({ settings, interfaceOptions = [], recommendedInterface = "", recommendedInterfaceLabel = "", isBusy = false, onChange, onSave }) {
  const hasInterfaces = interfaceOptions.length > 0;
  const recommendedLabel = recommendedInterfaceLabel
    ? `Auto (Recommended: ${recommendedInterfaceLabel})`
    : recommendedInterface
      ? "Auto (Recommended)"
      : "Auto";

  return (
    <div className="panel-body">
      <p className="eyebrow">Live Settings</p>
      <div className="settings-helper">
        <div>
          <h3>Capture Profile</h3>
          <p className="muted">
            Use Auto for the recommended adapter, or pin a specific interface when testing VPNs, VMware networks, or wired Ethernet.
          </p>
        </div>
        <span className={`ops-state-pill ${hasInterfaces ? "ops-healthy" : "ops-warning"}`}>
          {hasInterfaces ? `${interfaceOptions.length} interface(s)` : "Manual mode"}
        </span>
      </div>
      <div className="form-grid">
        <label>
          <span>Interface</span>
          {hasInterfaces ? (
            <select value={settings.iface || "iface=default"} onChange={(event) => onChange("iface", event.target.value)} disabled={isBusy}>
              <option value="iface=default">{recommendedLabel}</option>
              {interfaceOptions.map((item) => (
                <option key={item.value} value={item.value}>
                  {item.label}
                </option>
              ))}
            </select>
          ) : (
            <input value={settings.iface} onChange={(event) => onChange("iface", event.target.value)} disabled={isBusy} />
          )}
          {hasInterfaces ? (
            <small className="field-help">
              Default mode picks the active adapter automatically so external traffic shows up on the right card.
            </small>
          ) : null}
        </label>
        <label>
          <span>ML Threshold</span>
          <input type="number" min="0" max="1" step="0.01" value={settings.ids_ml_threshold} onChange={(event) => onChange("ids_ml_threshold", event.target.value)} disabled={isBusy} />
        </label>
        <label>
          <span>Trace Timeout</span>
          <input type="number" min="0.2" max="10" step="0.1" value={settings.tr_timeout} onChange={(event) => onChange("tr_timeout", event.target.value)} disabled={isBusy} />
        </label>
        <label>
          <span>Trace Mode</span>
          <select value={settings.tr_mode} onChange={(event) => onChange("tr_mode", event.target.value)} disabled={isBusy}>
            <option value="UDP">UDP</option>
            <option value="TCP">TCP</option>
            <option value="ICMP">ICMP</option>
          </select>
        </label>
        <label className="full-span">
          <span>Whitelist</span>
          <input value={settings.whitelist_ips} onChange={(event) => onChange("whitelist_ips", event.target.value)} placeholder="127.0.0.1, 192.168.1.1" disabled={isBusy} />
        </label>
        <label className="full-span">
          <span>Remote dashboard IP allowlist</span>
          <input value={settings.remote_dashboard_allowlist || ""} onChange={(event) => onChange("remote_dashboard_allowlist", event.target.value)} placeholder="203.0.113.10, 10.10.0.0/24" disabled={isBusy} />
          <small className="field-help">When Server Mode is enabled, only these client IPs/CIDRs can reach the remote dashboard.</small>
        </label>
        <label>
          <span>Retention minutes</span>
          <input type="number" min="0" max="525600" step="60" value={settings.retention_minutes || 0} onChange={(event) => onChange("retention_minutes", event.target.value)} disabled={isBusy} />
          <small className="field-help">0 keeps current behavior. Any positive value auto-cleans old packet/report rows.</small>
        </label>
        <label className="toggle">
          <input type="checkbox" checked={Boolean(settings.auto_block)} onChange={(event) => onChange("auto_block", event.target.checked)} disabled={isBusy} />
          <span>Auto block high-risk alerts</span>
        </label>
        <label className="toggle">
          <input type="checkbox" checked={Boolean(settings.persist_logs)} onChange={(event) => onChange("persist_logs", event.target.checked)} disabled={isBusy} />
          <span>Persist logs to storage</span>
        </label>
        <label className="toggle">
          <input type="checkbox" checked={Boolean(settings.payload_capture_enabled)} onChange={(event) => onChange("payload_capture_enabled", event.target.checked)} disabled={isBusy || Boolean(settings.alert_only_mode)} />
          <span>Enable redacted payload preview</span>
        </label>
        <label className="toggle">
          <input type="checkbox" checked={Boolean(settings.alert_only_mode)} onChange={(event) => onChange("alert_only_mode", event.target.checked)} disabled={isBusy} />
          <span>Alert-only mode, never store packet payload previews</span>
        </label>
        <label className="toggle full-span">
          <input type="checkbox" checked={Boolean(settings.safe_use_policy_accepted)} onChange={(event) => onChange("safe_use_policy_accepted", event.target.checked)} disabled={isBusy} />
          <span>I accept the Safe Use Policy for authorized defensive monitoring only</span>
        </label>
      </div>
      {isBusy ? <p className="table-status">Saving runtime settings...</p> : null}
      <button className="primary wide-button" onClick={onSave} disabled={isBusy}>Save Settings</button>
    </div>
  );
}
