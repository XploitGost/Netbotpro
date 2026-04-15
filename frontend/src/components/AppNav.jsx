const NAV_ITEMS = [
  { id: "monitor", label: "Monitor" },
  { id: "inspect", label: "Inspect" },
  { id: "settings", label: "Settings" },
  { id: "traceroute", label: "Traceroute" },
  { id: "exports", label: "Exports" },
  { id: "reports", label: "Reports" },
  { id: "offline", label: "Offline" },
];

export function AppNav({ activePage, onNavigate }) {
  return (
    <nav className="app-nav card">
      <div className="app-nav-copy">
        <p className="eyebrow">Workspace</p>
        <strong>NetBotPro Web</strong>
      </div>
      <div className="app-nav-actions">
        {NAV_ITEMS.map((item) => (
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
    </nav>
  );
}
