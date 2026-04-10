export function ExportPanel({ apiBase, error, exportInfo, onExport }) {
  return (
    <div className="panel-body">
      <p className="eyebrow">Session Export</p>
      <div className="stack">
        <div className="actions-row">
          <button className="secondary" onClick={() => onExport("csv")}>CSV</button>
          <button className="secondary" onClick={() => onExport("xlsx")}>XLSX</button>
          <button className="secondary" onClick={() => onExport("html")}>HTML</button>
          <button className="primary" onClick={() => onExport("zip")}>ZIP</button>
        </div>
        {exportInfo ? (
          <div className="export-box">
            <p className="muted">Last export</p>
            <p>{exportInfo.path}</p>
            <a href={`${apiBase}/exports/download?path=${encodeURIComponent(exportInfo.path)}`}>Download generated file</a>
          </div>
        ) : null}
        {error ? <p className="error">{error}</p> : null}
      </div>
    </div>
  );
}
