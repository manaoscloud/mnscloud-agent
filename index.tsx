import { createFileRoute } from "@tanstack/react-router";
import {
  GitPullRequest,
  ShieldCheck,
  Users,
  Code2,
  CheckCircle2,
  AlertTriangle,
  FileCode,
  Briefcase,
  ArrowUpRight,
  Github,
} from "lucide-react";
export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "Your App" },
      { name: "description", content: "Replace this with a one-sentence description of your app." },
      { property: "og:title", content: "Your App" },
      { property: "og:description", content: "Replace this with a one-sentence description of your app." },
      { title: "Contributing — MNSCloud" },
      {
        name: "description",
        content:
          "Guia oficial de contribuição da MNSCloud: fluxo de Pull Requests, padrões de código, regras de segurança e expectativas de revisão.",
      },
      { property: "og:title", content: "Contributing — MNSCloud" },
      {
        property: "og:description",
        content:
          "Guia oficial de contribuição da MNSCloud — padrões de engenharia, segurança e produto.",
      },
    ],
  }),
  component: Index,
  component: ContributingPage,
});
// IMPORTANT: Replace this placeholder. See ./README.md for routing conventions.
function Index() {
const sections = [
  { id: "model", label: "Contribution Model", icon: GitPullRequest },
  { id: "review", label: "Review & Acceptance", icon: CheckCircle2 },
  { id: "paid", label: "Paid & Hiring", icon: Briefcase },
  { id: "security", label: "Security Rules", icon: ShieldCheck },
  { id: "boundary", label: "Public Client Boundary", icon: FileCode },
  { id: "standards", label: "Coding Standards", icon: Code2 },
  { id: "validation", label: "Validation", icon: CheckCircle2 },
  { id: "pr", label: "PR Expectations", icon: GitPullRequest },
];
function ContributingPage() {
  return (
    <div
      className="flex min-h-screen items-center justify-center"
      style={{ backgroundColor: "#fcfbf8" }}
    >
      <img
        data-lovable-blank-page-placeholder="REMOVE_THIS"
        src="https://cdn.gpteng.co/blank-app-v1.svg"
        alt="Your app will live here!"
      />
    <div className="min-h-screen bg-background text-foreground">
      {/* Top Nav */}
      <header className="sticky top-0 z-40 border-b border-border/60 bg-background/80 backdrop-blur-xl">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-4">
          <a href="#top" className="flex items-center gap-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-md bg-gradient-accent shadow-glow">
              <span className="font-display text-sm font-bold text-primary-foreground">M</span>
            </div>
            <span className="font-display text-sm font-semibold tracking-tight">
              MNSCloud<span className="text-muted-foreground">/docs</span>
            </span>
          </a>
          <nav className="hidden items-center gap-8 md:flex">
            <a href="#model" className="text-sm text-muted-foreground transition-colors hover:text-foreground">
              Guidelines
            </a>
            <a href="#security" className="text-sm text-muted-foreground transition-colors hover:text-foreground">
              Security
            </a>
            <a href="#pr" className="text-sm text-muted-foreground transition-colors hover:text-foreground">
              Pull Requests
            </a>
          </nav>
          <a
            href="#"
            className="inline-flex items-center gap-2 rounded-md border border-border bg-surface px-3 py-1.5 text-xs font-medium transition-colors hover:bg-surface-elevated"
          >
            <Github className="h-3.5 w-3.5" />
            View on GitHub
            <ArrowUpRight className="h-3 w-3" />
          </a>
        </div>
      </header>
      {/* Hero */}
      <section id="top" className="relative overflow-hidden bg-gradient-hero">
        <div className="absolute inset-0 grid-pattern opacity-40" />
        <div className="absolute inset-x-0 bottom-0 h-px bg-gradient-to-r from-transparent via-primary/40 to-transparent" />
        <div className="relative mx-auto max-w-7xl px-6 py-24 md:py-32">
          <div className="inline-flex items-center gap-2 rounded-full border border-border bg-surface/60 px-3 py-1 font-mono text-xs uppercase tracking-wider text-muted-foreground backdrop-blur">
            <span className="h-1.5 w-1.5 rounded-full bg-indigo-glow shadow-glow" />
            v2026.06 · Public contributors
          </div>
          <h1 className="mt-6 max-w-4xl text-5xl font-bold leading-[1.05] tracking-tight md:text-7xl">
            Contributing to{" "}
            <span className="text-gradient">MNSCloud</span>
          </h1>
          <p className="mt-6 max-w-2xl text-lg text-muted-foreground md:text-xl">
            MNSCloud maintains public repositories so customers, partners, and the community can
            inspect, reuse, and improve selected clients, agents, installers, and connectors.
          </p>
          <div className="mt-10 flex flex-wrap gap-3">
            <a
              href="#model"
              className="inline-flex items-center gap-2 rounded-md bg-gradient-accent px-5 py-2.5 text-sm font-medium text-primary-foreground shadow-glow transition-transform hover:scale-[1.02]"
            >
              Start contributing
              <ArrowUpRight className="h-4 w-4" />
            </a>
            <a
              href="#security"
              className="inline-flex items-center gap-2 rounded-md border border-border bg-surface/60 px-5 py-2.5 text-sm font-medium backdrop-blur transition-colors hover:bg-surface-elevated"
            >
              <ShieldCheck className="h-4 w-4" />
              Security rules
            </a>
          </div>
          {/* Stats strip */}
          <div className="mt-16 grid grid-cols-2 gap-6 border-t border-border pt-8 md:grid-cols-4">
            {[
              ["PR-only", "Contribution flow"],
              ["Reviewed", "By maintainers"],
              ["Public", "Client boundary"],
              ["English", "Docs & comments"],
            ].map(([k, v]) => (
              <div key={k}>
                <div className="font-display text-2xl font-semibold tracking-tight">{k}</div>
                <div className="mt-1 text-xs uppercase tracking-wider text-muted-foreground">{v}</div>
              </div>
            ))}
          </div>
        </div>
      </section>
      {/* Section index */}
      <section className="border-y border-border bg-surface/40">
        <div className="mx-auto max-w-7xl px-6 py-8">
          <div className="mb-4 font-mono text-xs uppercase tracking-wider text-muted-foreground">
            // Sections
          </div>
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
            {sections.map(({ id, label, icon: Icon }) => (
              <a
                key={id}
                href={`#${id}`}
                className="group flex items-center gap-3 rounded-md border border-border bg-card p-3 transition-all hover:border-primary/60 hover:bg-surface-elevated"
              >
                <Icon className="h-4 w-4 text-indigo-glow" />
                <span className="text-sm font-medium">{label}</span>
              </a>
            ))}
          </div>
        </div>
      </section>
      <main className="mx-auto max-w-7xl px-6 py-20">
        {/* Contribution Model */}
        <Block id="model" tag="01" title="Contribution Model" icon={GitPullRequest}>
          <p>
            All contributions must go through a Pull Request. Direct pushes to{" "}
            <Code>main</Code> are not part of the contribution workflow.
          </p>
          <div className="mt-6 grid gap-6 lg:grid-cols-5">
            <div className="lg:col-span-2">
              <h4 className="font-display text-sm uppercase tracking-wider text-muted-foreground">
                Recommended flow
              </h4>
              <ol className="mt-4 space-y-3 text-sm">
                {[
                  "Create a feature branch",
                  "Make your changes",
                  "Run validation commands",
                  "Commit with a clear message",
                  "Open a PR against main",
                ].map((step, i) => (
                  <li key={step} className="flex gap-3">
                    <span className="font-mono text-xs text-indigo-glow">0{i + 1}</span>
                    <span className="text-foreground">{step}</span>
                  </li>
                ))}
              </ol>
            </div>
            <CodeBlock className="lg:col-span-3">
{`git checkout -b feature/clear-change-name
# make changes
# run the repository validation commands
git commit -m "Describe the change clearly"
git push origin feature/clear-change-name`}
            </CodeBlock>
          </div>
        </Block>
        {/* Review & Acceptance */}
        <Block id="review" tag="02" title="Review & Acceptance" icon={CheckCircle2}>
          <p>
            A contribution may be accepted, changed, postponed, or declined at the sole discretion
            of the MNSCloud maintainers. We review for:
          </p>
          <div className="mt-6 grid gap-3 md:grid-cols-2">
            {[
              "Product fit and long-term maintainability",
              "Security impact and tenant/customer isolation",
              "Compatibility with the public API contract",
              "Code quality, tests, documentation, operational safety",
              "Consistency with README, SKILL, AGENTS and domain docs",
            ].map((item) => (
              <div
                key={item}
                className="flex items-start gap-3 rounded-md border border-border bg-card p-4"
              >
                <CheckCircle2 className="mt-0.5 h-4 w-4 flex-shrink-0 text-indigo-glow" />
                <span className="text-sm">{item}</span>
              </div>
            ))}
          </div>
          <Callout>
            Please don't take requested changes personally. Review is part of keeping a
            production-grade platform trustworthy.
          </Callout>
        </Block>
        {/* Paid */}
        <Block id="paid" tag="03" title="Paid Contributions, Sponsorships & Hiring" icon={Briefcase}>
          <p>
            MNSCloud may, at its discretion, offer paid work, sponsorship, consulting contracts,
            bounties, or hiring conversations for contributors whose work demonstrates strong
            technical quality, reliability, and alignment with the platform.
          </p>
          <div className="mt-6 space-y-3">
            {[
              "Opening a Pull Request does not create an obligation for MNSCloud to pay for the work.",
              "Paid work requires explicit written agreement with MNSCloud before it is considered billable.",
              "Security-sensitive, large, roadmap, or customer-specific work should be discussed with maintainers first.",
              "MNSCloud may contact contributors privately when a contribution shows potential for deeper collaboration.",
            ].map((t, i) => (
              <div key={i} className="flex gap-4 rounded-md border border-border bg-card p-4">
                <span className="font-mono text-xs text-muted-foreground">→</span>
                <span className="text-sm">{t}</span>
              </div>
            ))}
          </div>
        </Block>
        {/* Security */}
        <Block id="security" tag="04" title="Security Rules" icon={ShieldCheck} accent>
          <p>Never commit or expose any of the following:</p>
          <div className="mt-6 grid gap-3 md:grid-cols-2">
            {[
              "Tokens, passwords, API keys, JWTs, private keys, signing secrets",
              "Provider credentials, database credentials, or master keys",
              "Customer data, production IPs/domains, account IDs",
              "Private topology, billing rules, internal policy rules",
              "Non-public business logic",
              "Hidden bypasses or static privileged credentials",
              "Client-side-only authorization enforcement",
            ].map((item) => (
              <div
                key={item}
                className="flex items-start gap-3 rounded-md border border-destructive/30 bg-destructive/5 p-4"
              >
                <AlertTriangle className="mt-0.5 h-4 w-4 flex-shrink-0 text-destructive" />
                <span className="text-sm">{item}</span>
              </div>
            ))}
          </div>
          <div className="mt-8">
            <h4 className="font-display text-sm uppercase tracking-wider text-muted-foreground">
              Use placeholders in examples
            </h4>
            <CodeBlock className="mt-3">
{`<api_base_url>
<token>
<tenant_domain>
<node_uuid>
<environment_uuid>`}
            </CodeBlock>
          </div>
          <Callout variant="warn">
            If you discover a vulnerability, do not open a public issue with exploit details.
            Follow <Code>SECURITY.md</Code> or contact the maintainers privately.
          </Callout>
        </Block>
        {/* Boundary */}
        <Block id="boundary" tag="05" title="Public Client Boundary" icon={FileCode}>
          <p>
            Public repositories are clients, agents, installers, or edge connectors. They consume
            the MNSCloud API contract — they are not the source of truth for authorization, tenant
            scope, billing, routing ownership, policy decisions, or secret resolution.
          </p>
          <div className="mt-6 rounded-md border border-primary/30 bg-surface p-6">
            <div className="font-mono text-xs uppercase tracking-wider text-indigo-glow">
              Source of truth
            </div>
            <div className="mt-2 font-display text-xl">
              Those decisions belong in the API / control plane.
            </div>
          </div>
        </Block>
        {/* Standards */}
        <Block id="standards" tag="06" title="Coding Standards" icon={Code2}>
          <div className="grid gap-3 md:grid-cols-2">
            {[
              ["English", "Keep documentation and code comments in English unless a file explicitly documents another language."],
              ["Reuse patterns", "Prefer existing repository patterns over new abstractions."],
              ["Stay focused", "Keep changes focused. Avoid unrelated refactors."],
              ["Tests & docs", "Add or update tests/docs when behavior changes."],
              ["Justify deps", "Do not add dependencies unless necessary and justified in the PR."],
              ["Strong defaults", "Do not weaken security defaults to make local testing easier."],
            ].map(([title, desc]) => (
              <div key={title} className="rounded-md border border-border bg-card p-5">
                <div className="font-display text-sm font-semibold">{title}</div>
                <div className="mt-2 text-sm text-muted-foreground">{desc}</div>
              </div>
            ))}
          </div>
        </Block>
        {/* Validation */}
        <Block id="validation" tag="07" title="Validation" icon={CheckCircle2}>
          <p>
            Before opening a Pull Request, run the validation commands documented in the
            repository <Code>README.md</Code> and <Code>SKILL.md</Code>. At minimum, run the
            CI-equivalent checks provided by this repository.
          </p>
          <CodeBlock className="mt-6">
{`$ npm run lint
$ npm run test
$ npm run build
# CI-equivalent checks must pass before review.`}
          </CodeBlock>
        </Block>
        {/* PR */}
        <Block id="pr" tag="08" title="Pull Request Expectations" icon={GitPullRequest}>
          <p>A good Pull Request includes:</p>
          <div className="mt-6 space-y-3">
            {[
              ["Clear summary", "What changed and why."],
              ["Validation evidence", "Test output, screenshots, manual checks."],
              ["UI screenshots", "For any visual or UI changes."],
              ["Impact notes", "API contract, database, installer, or security impact."],
              ["Dependency disclosure", "If the change introduces new dependencies or operational requirements."],
            ].map(([title, desc]) => (
              <div
                key={title}
                className="flex items-start gap-4 rounded-md border border-border bg-card p-5"
              >
                <CheckCircle2 className="mt-1 h-5 w-5 flex-shrink-0 text-indigo-glow" />
                <div>
                  <div className="font-display text-sm font-semibold">{title}</div>
                  <div className="mt-1 text-sm text-muted-foreground">{desc}</div>
                </div>
              </div>
            ))}
          </div>
        </Block>
        {/* CTA */}
        <div className="mt-24 overflow-hidden rounded-xl border border-border bg-gradient-hero">
          <div className="relative grid gap-8 p-10 md:grid-cols-[1fr_auto] md:items-center md:p-14">
            <div className="absolute inset-0 grid-pattern opacity-30" />
            <div className="relative">
              <div className="font-mono text-xs uppercase tracking-wider text-indigo-glow">
                Ready to contribute?
              </div>
              <h3 className="mt-3 font-display text-3xl font-bold tracking-tight md:text-4xl">
                Open your first Pull Request.
              </h3>
              <p className="mt-3 max-w-xl text-muted-foreground">
                Follow this guide, validate locally, and the maintainers will review your work
                against MNSCloud's engineering and security standards.
              </p>
            </div>
            <div className="relative flex flex-wrap gap-3">
              <a
                href="#"
                className="inline-flex items-center gap-2 rounded-md bg-gradient-accent px-5 py-2.5 text-sm font-medium text-primary-foreground shadow-glow"
              >
                <Github className="h-4 w-4" />
                Open repository
              </a>
              <a
                href="#top"
                className="inline-flex items-center gap-2 rounded-md border border-border bg-surface/60 px-5 py-2.5 text-sm font-medium backdrop-blur transition-colors hover:bg-surface-elevated"
              >
                Back to top
              </a>
            </div>
          </div>
        </div>
      </main>
      <footer className="border-t border-border">
        <div className="mx-auto flex max-w-7xl flex-col gap-4 px-6 py-10 md:flex-row md:items-center md:justify-between">
          <div className="flex items-center gap-2">
            <div className="flex h-6 w-6 items-center justify-center rounded bg-gradient-accent">
              <span className="font-display text-[10px] font-bold text-primary-foreground">M</span>
            </div>
            <span className="font-mono text-xs text-muted-foreground">
              © {new Date().getFullYear()} MNSCloud · Public contributors guide
            </span>
          </div>
          <div className="flex gap-6 text-xs text-muted-foreground">
            <a href="#security" className="hover:text-foreground">Security</a>
            <a href="#" className="hover:text-foreground">SECURITY.md</a>
            <a href="#" className="hover:text-foreground">License</a>
          </div>
        </div>
      </footer>
    </div>
  );
}
/* --- Building blocks --- */
function Block({
  id,
  tag,
  title,
  icon: Icon,
  children,
  accent,
}: {
  id: string;
  tag: string;
  title: string;
  icon: React.ComponentType<{ className?: string }>;
  children: React.ReactNode;
  accent?: boolean;
}) {
  return (
    <section id={id} className="scroll-mt-24 border-t border-border py-16 first:border-t-0">
      <div className="grid gap-10 lg:grid-cols-[280px_1fr]">
        <div className="lg:sticky lg:top-28 lg:self-start">
          <div className="font-mono text-xs uppercase tracking-wider text-muted-foreground">
            § {tag}
          </div>
          <div className="mt-3 flex items-center gap-3">
            <div
              className={`flex h-10 w-10 items-center justify-center rounded-md border ${
                accent
                  ? "border-primary/50 bg-primary/10 text-indigo-glow shadow-glow"
                  : "border-border bg-surface text-indigo-glow"
              }`}
            >
              <Icon className="h-5 w-5" />
            </div>
          </div>
          <h2 className="mt-4 font-display text-3xl font-bold tracking-tight md:text-4xl">
            {title}
          </h2>
        </div>
        <div className="prose-invert max-w-none text-base leading-relaxed text-muted-foreground [&_p]:text-muted-foreground">
          {children}
        </div>
      </div>
    </section>
  );
}
function Code({ children }: { children: React.ReactNode }) {
  return (
    <code className="rounded bg-surface-elevated px-1.5 py-0.5 font-mono text-[0.85em] text-indigo-glow">
      {children}
    </code>
  );
}
function CodeBlock({ children, className = "" }: { children: string; className?: string }) {
  return (
    <div className={`overflow-hidden rounded-lg border border-border bg-surface shadow-elevated ${className}`}>
      <div className="flex items-center gap-1.5 border-b border-border bg-surface-elevated px-4 py-2.5">
        <span className="h-2.5 w-2.5 rounded-full bg-destructive/60" />
        <span className="h-2.5 w-2.5 rounded-full bg-chart-4/60" style={{ background: "oklch(0.75 0.15 80)" }} />
        <span className="h-2.5 w-2.5 rounded-full bg-indigo-glow/60" />
        <span className="ml-3 font-mono text-xs text-muted-foreground">terminal</span>
      </div>
      <pre className="overflow-x-auto p-5 font-mono text-sm leading-relaxed text-foreground">
        <code>{children}</code>
      </pre>
    </div>
  );
}
function Callout({
  children,
  variant = "info",
}: {
  children: React.ReactNode;
  variant?: "info" | "warn";
}) {
  const styles =
    variant === "warn"
      ? "border-destructive/40 bg-destructive/5 text-foreground"
      : "border-primary/30 bg-primary/5 text-foreground";
  return (
    <div className={`mt-6 rounded-md border-l-2 p-4 text-sm ${styles}`}>{children}</div>
  );
}
