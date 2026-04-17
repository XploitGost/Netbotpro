import { useEffect, useState } from "react";

function cleanDisplay(value) {
  return String(value ?? "")
    .replaceAll("Ã¢â‚¬Â¢", "|")
    .replaceAll("â€¢", "|")
    .replaceAll("\u2022", "|")
    .trim();
}

function hasRows(rows) {
  return Array.isArray(rows) && rows.some((row) => {
    const value = cleanDisplay(row?.value);
    return value && value !== "-";
  });
}

function hasItems(groups) {
  return Array.isArray(groups) && groups.some((group) => Array.isArray(group?.items) && group.items.length);
}

function DetailSection({ title, rows, className = "" }) {
  if (!hasRows(rows)) return null;

  return (
    <section className={`detail-group ${className}`.trim()}>
      <h3>{title}</h3>
      <dl className="detail-grid inspection-grid">
        {rows
          .filter((row) => {
            const value = cleanDisplay(row?.value);
            return value && value !== "-";
          })
          .map((row) => (
            <div key={`${title}-${row.label}`}>
              <dt>{row.label}</dt>
              <dd>{cleanDisplay(row.value)}</dd>
            </div>
          ))}
      </dl>
    </section>
  );
}

function ApplicationDecodeSection({ groups }) {
  if (!Array.isArray(groups) || !groups.length) return null;

  return (
    <section className="detail-group">
      <h3>Application Decode</h3>
      <div className="inspection-subgroups">
        {groups.map((group) => (
          <div key={group.title} className="inspection-subgroup">
            <h4>{group.title}</h4>
            <dl className="detail-grid inspection-grid">
              {group.rows.map((row) => (
                <div key={`${group.title}-${row.label}`}>
                  <dt>{row.label}</dt>
                  <dd>{cleanDisplay(row.value)}</dd>
                </div>
              ))}
            </dl>
          </div>
        ))}
      </div>
    </section>
  );
}

function RelatedActivitySection({ groups }) {
  const visibleGroups = Array.isArray(groups) ? groups.filter((group) => Array.isArray(group?.items) && group.items.length) : [];
  if (!visibleGroups.length) return null;

  return (
    <section className="detail-group">
      <h3>Related Activity</h3>
      <div className="inspection-subgroups">
        {visibleGroups.map((group) => (
          <div key={group.title} className="inspection-subgroup">
            <h4>{group.title}</h4>
            <div className="inspection-activity-list">
              {group.items.map((item, index) => (
                <article key={`${group.title}-${index}`} className="inspection-activity-item">
                  <strong>{cleanDisplay(item.title)}</strong>
                  <p className="muted">{cleanDisplay(item.body)}</p>
                </article>
              ))}
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}

function BehaviorCorrelationSection({ groups }) {
  const visibleGroups = Array.isArray(groups)
    ? groups.filter((group) => hasRows(group?.rows) || (Array.isArray(group?.items) && group.items.length))
    : [];
  if (!visibleGroups.length) return null;

  return (
    <section className="detail-group">
      <h3>Behavior Correlation</h3>
      <div className="inspection-subgroups">
        {visibleGroups.map((group) => (
          <div key={group.title} className="inspection-subgroup">
            {group.eyebrow ? <p className="eyebrow">{cleanDisplay(group.eyebrow)}</p> : null}
            <h4>{cleanDisplay(group.title)}</h4>
            {hasRows(group.rows) ? (
              <dl className="detail-grid inspection-grid">
                {group.rows
                  .filter((row) => {
                    const value = cleanDisplay(row?.value);
                    return value && value !== "-";
                  })
                  .map((row) => (
                    <div key={`${group.title}-${row.label}`}>
                      <dt>{row.label}</dt>
                      <dd>{cleanDisplay(row.value)}</dd>
                    </div>
                  ))}
              </dl>
            ) : null}
            {Array.isArray(group?.items) && group.items.length ? (
              <div className="inspection-activity-list inspection-activity-list-compact">
                {group.items.map((item, index) => (
                  <article key={`${group.title}-${index}`} className="inspection-activity-item">
                    <strong>{cleanDisplay(item.title)}</strong>
                    <p className="muted">{cleanDisplay(item.body)}</p>
                  </article>
                ))}
              </div>
            ) : null}
          </div>
        ))}
      </div>
    </section>
  );
}

function StreamActionButton({ item, actions }) {
  if (!item || !actions) return null;
  if (item.actionKind === "packet" && item.actionId && typeof actions.onOpenPacket === "function") {
    return (
      <button type="button" className="secondary mini-list-link" onClick={() => actions.onOpenPacket(item.actionId)}>
        {cleanDisplay(item.actionLabel || "Open Packet")}
      </button>
    );
  }
  if (item.actionKind === "alert" && item.actionId && typeof actions.onOpenAlert === "function") {
    return (
      <button type="button" className="secondary mini-list-link" onClick={() => actions.onOpenAlert(item.actionId)}>
        {cleanDisplay(item.actionLabel || "Open Alert")}
      </button>
    );
  }
  if (item.actionKind === "process" && typeof actions.onFilterProcess === "function" && (cleanDisplay(item.processName) || cleanDisplay(item.pid))) {
    return (
      <button
        type="button"
        className="secondary mini-list-link"
        onClick={() => actions.onFilterProcess({ process_name: item.processName || "", pid: item.pid || "" })}
      >
        {cleanDisplay(item.actionLabel || "Filter Process")}
      </button>
    );
  }
  return null;
}

function StreamIntelligenceSection({ rows, groups, actions }) {
  const visibleGroups = Array.isArray(groups) ? groups.filter((group) => Array.isArray(group?.items) && group.items.length) : [];
  if (!hasRows(rows) && !visibleGroups.length) return null;

  return (
    <section className="detail-group">
      <h3>Stream Intelligence</h3>
      {hasRows(rows) ? (
        <dl className="detail-grid inspection-grid">
          {rows
            .filter((row) => {
              const value = cleanDisplay(row?.value);
              return value && value !== "-";
            })
            .map((row) => (
              <div key={`stream-${row.label}`}>
                <dt>{cleanDisplay(row.label)}</dt>
                <dd>{cleanDisplay(row.value)}</dd>
              </div>
            ))}
        </dl>
      ) : null}
      {visibleGroups.length ? (
        <div className="inspection-subgroups">
          {visibleGroups.map((group) => (
            <div key={group.title} className="inspection-subgroup">
              <h4>{cleanDisplay(group.title)}</h4>
              <div className="inspection-activity-list">
                {group.items.map((item, index) => (
                  <article key={`${group.title}-${index}`} className="inspection-activity-item">
                    <strong>{cleanDisplay(item.title)}</strong>
                    <p className="muted">{cleanDisplay(item.body)}</p>
                    <StreamActionButton item={item} actions={actions} />
                  </article>
                ))}
              </div>
            </div>
          ))}
        </div>
      ) : null}
    </section>
  );
}

function PayloadSection({ payload, rows, selectionKey }) {
  const [activeTab, setActiveTab] = useState("decoded");

  useEffect(() => {
    setActiveTab(payload?.tabs?.[0]?.id || "decoded");
  }, [selectionKey]);

  if (!payload && !hasRows(rows)) return null;
  const activePayload = payload?.tabs?.find((tab) => tab.id === activeTab) || payload?.tabs?.[0];

  return (
    <section className="detail-group">
      <h3>Payload</h3>
      {hasRows(rows) ? (
        <dl className="detail-grid inspection-grid">
          {rows
            .filter((row) => {
              const value = cleanDisplay(row?.value);
              return value && value !== "-";
            })
            .map((row) => (
              <div key={`payload-${row.label}`}>
                <dt>{row.label}</dt>
                <dd>{cleanDisplay(row.value)}</dd>
              </div>
            ))}
        </dl>
      ) : null}
      {payload?.tabs?.length ? (
        <div className="payload-tabs">
          <div className="payload-tab-row" role="tablist" aria-label="Payload views">
            {payload.tabs.map((tab) => (
              <button
                key={tab.id}
                type="button"
                role="tab"
                className={`payload-tab ${activePayload?.id === tab.id ? "payload-tab-active" : ""}`}
                aria-selected={activePayload?.id === tab.id}
                onClick={() => setActiveTab(tab.id)}
              >
                {tab.label}
              </button>
            ))}
          </div>
          <pre className="payload-preview">{cleanDisplay(activePayload?.value || "No payload preview available.")}</pre>
        </div>
      ) : null}
    </section>
  );
}

function RiskExplanationSection({ panel }) {
  if (!panel || (!hasRows(panel.rows) && !hasItems(panel.groups) && !cleanDisplay(panel.narrative))) return null;

  return (
    <section className="detail-group">
      <h3>Risk & Explanation</h3>
      {cleanDisplay(panel.narrative) ? <p className="muted inspection-narrative">{cleanDisplay(panel.narrative)}</p> : null}
      {hasRows(panel.rows) ? (
        <dl className="detail-grid inspection-grid">
          {panel.rows
            .filter((row) => {
              const value = cleanDisplay(row?.value);
              return value && value !== "-";
            })
            .map((row) => (
              <div key={`risk-${row.label}`}>
                <dt>{cleanDisplay(row.label)}</dt>
                <dd>{cleanDisplay(row.value)}</dd>
              </div>
            ))}
        </dl>
      ) : null}
      {hasItems(panel.groups) ? (
        <div className="inspection-subgroups">
          {panel.groups
            .filter((group) => Array.isArray(group?.items) && group.items.length)
            .map((group) => (
              <div key={group.title} className="inspection-subgroup">
                <h4>{cleanDisplay(group.title)}</h4>
                <div className="inspection-activity-list">
                  {group.items.map((item, index) => (
                    <article key={`${group.title}-${index}`} className="inspection-activity-item">
                      <strong>{cleanDisplay(item.title)}</strong>
                      <p className="muted">{cleanDisplay(item.body)}</p>
                    </article>
                  ))}
                </div>
              </div>
            ))}
        </div>
      ) : null}
    </section>
  );
}

function InspectionControls({ navigation }) {
  if (!navigation) return null;

  return (
    <div className="inspection-controls">
      <div className="inspection-nav-buttons">
        <button type="button" className="secondary" onClick={navigation.onPrevious} disabled={!navigation.canPrevious}>
          Prev
        </button>
        <button type="button" className="secondary" onClick={navigation.onNext} disabled={!navigation.canNext}>
          Next
        </button>
      </div>
      <div className="inspection-nav-buttons">
        <button type="button" className="secondary" onClick={navigation.onPin} disabled={!navigation.canPin}>
          {navigation.pinned ? "Unpin" : "Pin"}
        </button>
        <button type="button" className="secondary" onClick={navigation.onFreeze}>
          {navigation.frozen ? "Resume Live" : "Freeze Live"}
        </button>
      </div>
    </div>
  );
}

export function DetailPanel({ title, model, selectionKey = "", emptyMessage = "Select a row to inspect details", navigation = null }) {
  const [activeTab, setActiveTab] = useState(model?.investigationTabs?.[0]?.id || "");

  useEffect(() => {
    setActiveTab(model?.investigationTabs?.[0]?.id || "");
  }, [selectionKey, model?.investigationTabs?.[0]?.id]);

  if (!model || model.empty) {
    return (
      <div className="mini-panel detail-panel">
        <p className="eyebrow">{title}</p>
        <p className="muted">{emptyMessage}</p>
      </div>
    );
  }

  const activeSections = new Set(
    (Array.isArray(model.investigationTabs) && model.investigationTabs.length
      ? (model.investigationTabs.find((tab) => tab.id === activeTab) || model.investigationTabs[0])?.sections || []
      : ["hero", "verdict", "network", "transport", "process", "flow", "stream", "correlation", "related", "application", "payload", "enrichment", "risk", "raw"])
  );
  const showSection = (key) => activeSections.has(key);

  return (
    <div className="mini-panel detail-panel inspection-panel">
      <p className="eyebrow">{title}</p>
      <InspectionControls navigation={navigation} />
      {Array.isArray(model.investigationTabs) && model.investigationTabs.length ? (
        <div className="inspection-tab-row" role="tablist" aria-label={`${title} views`}>
          {model.investigationTabs.map((tab) => (
            <button
              key={tab.id}
              type="button"
              role="tab"
              className={`payload-tab ${activeTab === tab.id ? "payload-tab-active" : ""}`}
              aria-selected={activeTab === tab.id}
              onClick={() => setActiveTab(tab.id)}
            >
              {cleanDisplay(tab.label)}
            </button>
          ))}
        </div>
      ) : null}
      <div className="detail-panel-scroll">
        <div className="detail-sections">
          {showSection("hero") ? (
            <section className={`detail-group inspection-hero inspection-hero-${model.tone || "focus"}`}>
              <div className="inspection-hero-copy">
                <h3>{cleanDisplay(model.headline || title)}</h3>
                <p className="muted">{cleanDisplay(model.summaryText || model.interpretedSummary || "")}</p>
              </div>
            </section>
          ) : null}
          {showSection("verdict") ? <DetailSection title="Quick Verdict" rows={model.verdictRows} /> : null}
          {showSection("network") ? <DetailSection title="Network Path" rows={model.networkRows} /> : null}
          {showSection("transport") ? <DetailSection title="Transport & Protocol" rows={model.transportRows} /> : null}
          {showSection("process") ? <DetailSection title="Process & Host Correlation" rows={model.processRows} /> : null}
          {showSection("flow") ? <DetailSection title="Flow & Session" rows={model.flowRows} /> : null}
          {showSection("stream") ? <StreamIntelligenceSection rows={model.streamRows} groups={model.streamGroups} actions={navigation} /> : null}
          {showSection("risk") ? <RiskExplanationSection panel={model.riskExplanation} /> : null}
          {showSection("correlation") ? <BehaviorCorrelationSection groups={model.correlationGroups} /> : null}
          {showSection("related") ? <RelatedActivitySection groups={model.relatedGroups} /> : null}
          {showSection("application") ? <ApplicationDecodeSection groups={model.applicationGroups} /> : null}
          {showSection("payload") ? <PayloadSection payload={model.payload} rows={model.payloadRows} selectionKey={selectionKey} /> : null}
          {showSection("enrichment") ? <DetailSection title="Enrichment" rows={model.enrichmentRows} /> : null}
          {showSection("raw") ? <DetailSection title="Raw Metadata" rows={model.rawRows} className="detail-group-raw" /> : null}
        </div>
      </div>
    </div>
  );
}
