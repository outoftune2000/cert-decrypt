import Link from "next/link";

const TOOL_LINKS = [
  {
    href: "/entry-decoder",
    title: "Entry Decoder",
    description: "Decode CT entries and run fingerprint search windows."
  },
  {
    href: "/ct-live-tail",
    title: "CT Live Tail",
    description: "Monitor selected sources live with decoded output and tree-size diff checks."
  },
  {
    href: "/organization-only",
    title: "Organization-Only",
    description: "Scan CT ranges and filter rows that include organization values."
  },
  {
    href: "/range-ingest",
    title: "Range Ingest",
    description: "Bulk ingest ranges in 1024-entry chunks with existing-index checks."
  },
  {
    href: "/domain-lookup",
    title: "Domain Lookup",
    description: "Query subdomains and validity metadata for a root domain."
  },
  {
    href: "/domain-desc-search",
    title: "Descending Domain Search",
    description: "Search backward from latest Cloudflare indexes in live batches."
  },
  {
    href: "/index-compare",
    title: "Index Compare",
    description: "Compare two CT indexes and score relationship confidence."
  }
];

export default function HomePage() {
  return (
    <main className="page">
      <section className="results">
        <div className="home-grid">
          {TOOL_LINKS.map((tool) => (
            <Link key={tool.href} href={tool.href} className="home-link">
              <h3>{tool.title}</h3>
              <p>{tool.description}</p>
              <span>Open {tool.href}</span>
            </Link>
          ))}
        </div>
      </section>
    </main>
  );
}
