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
        <label className="toggle">
          <input type="checkbox" checked={Boolean(settings.auto_block)} onChange={(event) => onChange("auto_block", event.target.checked)} disabled={isBusy} />
          <span>Auto block high-risk alerts</span>
        </label>
        <label className="toggle">
          <input type="checkbox" checked={Boolean(settings.persist_logs)} onChange={(event) => onChange("persist_logs", event.target.checked)} disabled={isBusy} />
          <span>Persist logs to storage</span>
        </label>
      </div>
      {isBusy ? <p className="table-status">Saving runtime settings...</p> : null}
      <button className="primary wide-button" onClick={onSave} disabled={isBusy}>Save Settings</button>
    </div>
  );
}
