export function ReportsPanel({ onDownload, reports }) {
  return (
    <div className="panel-body">
      <p className="eyebrow">Generated Reports</p>
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
              <tr><td colSpan="3" className="muted">No reports yet</td></tr>
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
