export function ExportPanel({ error, exportInfo, onDownload, onExport }) {
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
            <button className="secondary" onClick={() => onDownload(exportInfo.path)}>Download generated file</button>
          </div>
        ) : null}
        {error ? <p className="error">{error}</p> : null}
      </div>
    </div>
  );
}
