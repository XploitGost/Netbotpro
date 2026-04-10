export function SectionBlock({ eyebrow, title, description, children }) {
  return (
    <section className="section-block">
      <div className="section-heading">
        <p className="eyebrow">{eyebrow}</p>
        <h2 className="section-title">{title}</h2>
        {description ? <p className="section-copy">{description}</p> : null}
      </div>
      {children}
    </section>
  );
}
