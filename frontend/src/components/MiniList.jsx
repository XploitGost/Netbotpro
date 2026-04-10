export function MiniList({ title, items, onSelect }) {
  return (
    <section className="mini-panel mini-list-panel">
      <p className="eyebrow">{title}</p>
      <ul className="mini-list">
        {items.length === 0 ? <li className="muted">No data yet</li> : null}
        {items.map((item) => (
          <li key={`${title}-${item.label}`}>
            {onSelect ? (
              <button className="table-link mini-list-link" onClick={() => onSelect(item)}>{item.label}</button>
            ) : (
              <span>{item.label}</span>
            )}
            <strong>{item.count}</strong>
          </li>
        ))}
      </ul>
    </section>
  );
}
