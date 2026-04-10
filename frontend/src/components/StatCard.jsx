export function StatCard({ label, value, hint }) {
  return (
    <section className="card stat-card">
      <p className="eyebrow">{label}</p>
      <h2>{value}</h2>
      <p className="muted">{hint}</p>
    </section>
  );
}
