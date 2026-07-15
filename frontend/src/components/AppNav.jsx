const NAV_GROUPS = [
  {
    label: "Analyze",
    items: [
      { id: "monitor", label: "Monitor" },
      { id: "inspect", label: "Inspect" },
      { id: "flows", label: "Flows" },
      { id: "incidents", label: "Incidents" },
    ],
  },
  {
    label: "Operations",
    items: [
      { id: "agents", label: "Agents" },
      { id: "traceroute", label: "Traceroute" },
      { id: "offline", label: "Offline" },
    ],
  },
  {
    label: "Output",
    items: [
      { id: "reports", label: "Reports" },
      { id: "exports", label: "Exports" },
      { id: "settings", label: "Settings" },
    ],
  },
];

export function AppNav({ activePage, onNavigate }) {
  return (
    <nav className="app-nav card">
      <div className="app-nav-copy">
        <p className="eyebrow">Workspace</p>
        <strong>NetBotPro Web</strong>
      </div>
      <div className="app-nav-actions">
        {NAV_GROUPS.map((group) => (
          <div key={group.label} className="nav-group">
            <span className="nav-group-label">{group.label}</span>
            <div className="nav-group-items">
              {group.items.map((item) => (
                <button
                  key={item.id}
                  type="button"
                  className={activePage === item.id ? "primary nav-button" : "secondary nav-button"}
                  onClick={() => onNavigate(item.id)}
                >
                  {item.label}
                </button>
              ))}
            </div>
          </div>
        ))}
      </div>
    </nav>
  );
}
