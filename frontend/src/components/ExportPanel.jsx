export function ExportPanel({ error, exportInfo, isBusy = false, onDownload, onExport }) {
  return (
    <div className="panel-body">
      <p className="eyebrow">Session Export</p>
      <div className="stack">
        <div className="actions-row">
          <button className="secondary" disabled={isBusy} onClick={() => onExport("csv")}>CSV</button>
          <button className="secondary" disabled={isBusy} onClick={() => onExport("xlsx")}>XLSX</button>
          <button className="secondary" disabled={isBusy} onClick={() => onExport("html")}>HTML</button>
          <button className="primary" disabled={isBusy} onClick={() => onExport("zip")}>ZIP</button>
        </div>
        {isBusy ? <p className="table-status">Preparing export files...</p> : null}
        {exportInfo ? (
          <div className="export-box">
            <p className="muted">Last export</p>
            <p>{exportInfo.path}</p>
            <p className="muted">{exportInfo.kind ? `${exportInfo.kind} report` : `${exportInfo.format} export`}</p>
            <button className="secondary" disabled={isBusy} onClick={() => onDownload(exportInfo.path)}>Download generated file</button>
          </div>
        ) : null}
        {!exportInfo && !isBusy && !error ? <p className="table-empty">Generate CSV, XLSX, HTML, ZIP, or investigation reports from the current workspace.</p> : null}
        {error ? <p className="error">{error}</p> : null}
      </div>
    </div>
  );
}
