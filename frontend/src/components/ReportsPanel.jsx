export function ReportsPanel({ isLoading = false, onDownload, reports }) {
  return (
    <div className="panel-body">
      <p className="eyebrow">Generated Reports</p>
      {isLoading ? <p className="table-status">Refreshing generated reports...</p> : null}
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Size</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {reports.length === 0 ? (
              <tr><td colSpan="3" className="table-empty">{isLoading ? "Loading report archive..." : "No reports yet. Generate an export or investigation report to populate this archive."}</td></tr>
            ) : reports.map((report) => (
              <tr key={report.path}>
                <td>{report.name}</td>
                <td>{report.size}</td>
                <td>
                  <button className="secondary" onClick={() => onDownload(report.path)}>Download</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
