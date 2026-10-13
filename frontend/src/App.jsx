import { useEffect, useState } from "react";
import "./App.css";

const API = (import.meta.env.VITE_API_BASE_URL || "/api").replace(/\/$/, "");
const ACTIVE = ["queued", "running"];
const STATUS = {
  queued: "Queued",
  running: "Investigating",
  awaiting_approval: "Review ready",
  approved: "Patch approved",
  complete: "Analysis complete",
  needs_review: "Analysis incomplete",
  failed: "Mission failed",
};

function Icon({ name = "shield", size = 20 }) {
  const paths = {
    shield: "M12 3 4 6v6c0 5 8 9 8 9s8-4 8-9V6l-8-3Zm-4 9 3 3 5-6",
    grid: "M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z",
    pulse: "M2 12h5l3-8 4 16 3-8h5",
    arrow: "M4 12h16m-6-6 6 6-6 6",
    check: "m5 12 4 4L19 6",
    download: "M12 3v12m-5-5 5 5 5-5M4 16v5h16v-5",
    code: "m8 6-6 6 6 6m8-12 6 6-6 6m-3-14-2 16",
    cloud: "M6 18a5 5 0 0 1-1-10 7 7 0 0 1 13-1 5.5 5.5 0 0 1 0 11H6Z",
    clock: "M12 8v5l3 2M22 12a10 10 0 1 1-20 0 10 10 0 0 1 20 0",
  };
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.6"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d={paths[name] || paths.shield} />
    </svg>
  );
}

async function request(path, options) {
  const response = await fetch(`${API}${path}`, options);
  const data = await response.json();
  if (!response.ok)
    throw new Error(
      typeof data.detail === "string"
        ? data.detail
        : `Request failed (${response.status})`,
    );
  return data;
}
const post = (body) => ({
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify(body),
});

function App() {
  const [repoUrl, setRepoUrl] = useState("");
  const [planner, setPlanner] = useState("policy");
  const [capabilities, setCapabilities] = useState(null);
  const [history, setHistory] = useState([]);
  const [id, setId] = useState(null);
  const [mission, setMission] = useState(null);
  const [tab, setTab] = useState("investigation");
  const [selected, setSelected] = useState(null);
  const [filter, setFilter] = useState("ALL");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [reviewed, setReviewed] = useState(false);

  useEffect(() => {
    let alive = true;
    Promise.all([request("/missions/capabilities"), request("/missions")])
      .then(([c, h]) => {
        if (alive) {
          setCapabilities(c);
          setHistory(h);
        }
      })
      .catch(() => {
        if (alive)
          setError(
            "Backend unavailable. Start the API and refresh to connect.",
          );
      });
    return () => {
      alive = false;
    };
  }, []);

  useEffect(() => {
    if (!id) return;
    let alive = true;
    let timer;
    async function poll() {
      try {
        const data = await request(`/missions/${id}`);
        if (!alive) return;
        setMission(data);
        if (ACTIVE.includes(data.status)) timer = setTimeout(poll, 900);
        else {
          const h = await request("/missions");
          if (alive) setHistory(h);
        }
      } catch (err) {
        if (alive) setError(err.message);
      }
    }
    poll();
    return () => {
      alive = false;
      clearTimeout(timer);
    };
  }, [id]);

  async function start(source) {
    if (source === "github" && !repoUrl.trim()) {
      setError("Enter a GitHub repository URL to investigate.");
      return;
    }
    setBusy(true);
    setError("");
    setReviewed(false);
    setSelected(null);
    setFilter("ALL");
    setTab("investigation");
    try {
      const data = await request(
        "/missions",
        post({ source, repo_url: repoUrl.trim(), planner }),
      );
      setMission(null);
      setId(data.id);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function approve() {
    setBusy(true);
    setError("");
    try {
      const data = await request(
        `/missions/${id}/approve`,
        post({ patch_sha256: mission.patch_sha256 }),
      );
      setMission(data);
      setHistory(await request("/missions"));
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function download(kind) {
    try {
      const response = await fetch(`${API}/missions/${id}/${kind}`);
      if (!response.ok)
        throw new Error(
          "Export unavailable. Review the mission status and try again.",
        );
      const url = URL.createObjectURL(await response.blob());
      const a = document.createElement("a");
      a.href = url;
      a.download = `cloudguard-${id.slice(0, 8)}.${kind === "patch" ? "patch" : "json"}`;
      a.click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (err) {
      setError(err.message);
    }
  }

  function openHistory(item) {
    setId(item.id);
    setMission(null);
    setSelected(null);
    setReviewed(false);
    setError("");
    setFilter("ALL");
  }

  const running = busy || (id && !mission) || ACTIVE.includes(mission?.status);
  const findings = mission?.findings || [];
  const resolved = new Set(mission?.verification?.resolved_ids || []);
  const visible = findings.filter(
    (f) =>
      filter === "ALL" ||
      (filter === "RESOLVED" ? resolved.has(f.id) : f.severity === filter),
  );
  const detail = findings.find((f) => f.id === selected) || visible[0];
  const risk = mission?.before?.risk_points;
  const after = mission?.after?.risk_points;
  const reduction = risk
    ? Math.round(((risk - (after ?? risk)) / risk) * 100)
    : 0;

  return (
    <div className="shell">
      <aside className="sidebar">
        <a className="brand" href="#main">
          <span className="brand-icon">
            <Icon size={25} />
          </span>
          <span>
            CloudGuard<span className="brand-sub">SECURITY WORKSPACE</span>
          </span>
        </a>
        <div className="workspace-tag">
          <span className="workspace-icon">CG</span>
          <div>
            Project workspace<small>Development environment</small>
          </div>
          <span className="tiny-dot" />
        </div>
        <p className="nav-label">WORKSPACE</p>
        <button
          className="nav-item active"
          onClick={() => {
            setTab("investigation");
            document.getElementById("main").focus();
          }}
        >
          <Icon name="grid" /> Security missions{" "}
          <span className="nav-count">{history.length}</span>
        </button>
        <button
          className="nav-item"
          onClick={() => {
            setTab("remediation");
            document
              .getElementById("analysis")
              ?.scrollIntoView({ behavior: "smooth" });
          }}
        >
          <Icon name="code" /> Remediation review
        </button>
        <button
          className="nav-item"
          onClick={() => {
            setTab("evidence");
            document
              .getElementById("analysis")
              ?.scrollIntoView({ behavior: "smooth" });
          }}
        >
          <Icon name="pulse" /> Evidence & activity
        </button>
        <div className="history-heading">
          <p className="nav-label">RECENT MISSIONS</p>
          <span>{history.length.toString().padStart(2, "0")}</span>
        </div>
        <div className="history-list">
          {history.length ? (
            history.slice(0, 6).map((item) => (
              <button
                className={`history-item ${id === item.id ? "selected" : ""}`}
                key={item.id}
                onClick={() => openHistory(item)}
              >
                <span className={`mission-dot ${item.status}`} />
                <span>
                  {item.repository}
                  <small>
                    {STATUS[item.status]} ·{" "}
                    {new Date(item.created_at).toLocaleTimeString([], {
                      hour: "2-digit",
                      minute: "2-digit",
                    })}
                  </small>
                </span>
              </button>
            ))
          ) : (
            <p className="empty-history">
              Your investigations will appear here.
            </p>
          )}
        </div>
        <div className="sidebar-bottom">
          <span className="tag-outline">AWS + CONTAINERS</span>
          <h3>Security before shipping.</h3>
          <p>
            Find the risk. Review the fix.
            <br />
            Keep the evidence.
          </p>
          <div className="local-note">
            <span className="tiny-dot" /> Local review workspace
          </div>
        </div>
      </aside>

      <div className="main-wrap">
        <header className="topbar">
          <div>
            <span className="muted">Workspace</span>
            <span className="slash">/</span>Security missions
          </div>
          <div className="connection">
            <span className={`tiny-dot ${capabilities ? "" : "offline"}`} />
            {capabilities ? "API connected" : "Connecting to API"}
            <span className="avatar">CG</span>
          </div>
        </header>
        <main id="main" tabIndex={-1}>
          <div className="page-heading">
            <div>
              <p className="eyebrow">
                <span /> CLOUD SECURITY, WITH A NEXT STEP
              </p>
              <h1>
                From finding to <span>verified fix.</span>
              </h1>
              <p className="subtitle">
                Investigate your deployment risks. Let the agent build the plan.
                You approve the change.
              </p>
            </div>
            <span className="phase-badge">
              SECURE <Icon name="arrow" size={13} /> BUILD{" "}
              <Icon name="arrow" size={13} /> DEPLOY
            </span>
          </div>

          <section
            className="launch-card"
            aria-label="Start a security mission"
          >
            <div className="launch-title">
              <span className="small-icon">
                <Icon name="cloud" />
              </span>
              <div>
                <h2>Start an investigation</h2>
                <p>
                  AWS infrastructure, source code, secrets, and Docker
                  configuration.
                </p>
              </div>
              <span className="read-only">READ-ONLY SOURCE</span>
            </div>
            <form
              className="launch-form"
              onSubmit={(e) => {
                e.preventDefault();
                start("github");
              }}
            >
              <label className="repo-field">
                <Icon name="code" />
                <span className="sr-only">GitHub repository URL</span>
                <input
                  type="url"
                  placeholder="https://github.com/your-team/your-project"
                  value={repoUrl}
                  onChange={(e) => setRepoUrl(e.target.value)}
                  disabled={running}
                />
              </label>
              <button
                className="button primary"
                type="submit"
                disabled={running || !capabilities}
              >
                {running ? "Investigating…" : "Run mission"}
                <Icon name="arrow" size={17} />
              </button>
            </form>
            <div className="launch-footer">
              <label className="planner-label">
                Planner
                <select
                  aria-label="Planner"
                  value={planner}
                  onChange={(e) => setPlanner(e.target.value)}
                  disabled={running}
                >
                  <option value="policy">Built-in policy</option>
                  <option value="ai" disabled={!capabilities?.ai_available}>
                    AI agent
                    {!capabilities?.ai_available ? " · key required" : ""}
                  </option>
                </select>
              </label>
              <span className="demo-note">
                Try an intentionally vulnerable AWS stack
              </span>
              <button
                className="text-button"
                onClick={() => start("demo")}
                disabled={running || !capabilities}
              >
                Run demo mission <Icon name="arrow" size={15} />
              </button>
            </div>
          </section>
          {error && (
            <div className="error-banner" role="alert">
              {error}
              <button aria-label="Dismiss error" onClick={() => setError("")}>
                ×
              </button>
            </div>
          )}

          {!id ? (
            <section className="welcome-grid">
              <div className="welcome-main">
                <span className="eyebrow">YOUR NEXT SECURITY REVIEW</span>
                <h2>A scan is only the beginning.</h2>
                <p>
                  Turn configuration findings into a reviewable patch—with a
                  record of what changed and what still needs your attention.
                </p>
                <div className="welcome-flow">
                  {[
                    ["01", "Investigate", "Collect concrete evidence"],
                    ["02", "Plan & stage", "Bounded remediation tools"],
                    ["03", "Verify & review", "Rescan before approval"],
                  ].map(([n, title, text]) => (
                    <div key={n}>
                      <span>{n}</span>
                      <h3>{title}</h3>
                      <p>{text}</p>
                    </div>
                  ))}
                </div>
              </div>
              <div className="scope-card">
                <Icon name="shield" size={30} />
                <h3>Honest by design</h3>
                <p>
                  Static findings are evidence of configuration risk. They are
                  not proof of an exploit or a live AWS assessment.
                </p>
                <span className="tag-outline">NO CLOUD CREDENTIALS NEEDED</span>
              </div>
            </section>
          ) : (
            <>
              <div className="mission-heading">
                <div>
                  <p className="eyebrow">
                    {mission?.source === "demo"
                      ? "DEMO INVESTIGATION"
                      : "REPOSITORY INVESTIGATION"}
                  </p>
                  <h2>{mission?.repository || "Preparing mission…"}</h2>
                  <p className="mission-meta">
                    {mission?.planner === "ai"
                      ? "AI tool-calling agent"
                      : "Built-in policy planner"}{" "}
                    <span>·</span> {id.slice(0, 8)}{" "}
                    {mission?.commit && (
                      <>
                        <span>·</span> commit {mission.commit.slice(0, 8)}
                      </>
                    )}
                  </p>
                </div>
                <div className="mission-actions">
                  <span
                    className={`status-pill ${mission?.status || "running"}`}
                    aria-live="polite"
                  >
                    <span className="tiny-dot" />
                    {STATUS[mission?.status] || "Preparing"}
                  </span>
                  <button
                    className="button subtle"
                    disabled={!mission?.finished_at}
                    onClick={() => download("report")}
                  >
                    <Icon name="download" size={16} /> Export report
                  </button>
                </div>
              </div>
              {mission?.error && (
                <div className="error-banner" role="alert">
                  {mission.error}
                </div>
              )}
              <section className="metrics" aria-label="Mission metrics">
                <Metric
                  label="INITIAL RISK POINTS"
                  value={risk ?? "—"}
                  suffix="pts"
                  detail="Weighted static findings"
                />
                <Metric
                  label="FINDINGS RESOLVED"
                  value={mission?.verification ? resolved.size : "—"}
                  suffix={findings.length ? `/ ${findings.length}` : ""}
                  detail="Verified in the proposed patch"
                  accent
                />
                <Metric
                  label="RISK REDUCTION"
                  value={after !== undefined ? `${reduction}%` : "—"}
                  detail={
                    after !== undefined
                      ? `${risk} → ${after} points · static heuristic`
                      : "Measured after verification"
                  }
                />
                <div className="metric gate-metric">
                  <p>RESIDUAL SECURITY GATE</p>
                  <strong
                    className={
                      mission?.after?.gate === "BLOCKED" ? "text-orange" : ""
                    }
                  >
                    {mission?.after?.gate || mission?.before?.gate || "PENDING"}
                  </strong>
                  <span>
                    {mission?.after?.total !== undefined
                      ? `${mission.after.total} finding(s) still need review`
                      : "Waiting for scan evidence"}
                  </span>
                </div>
              </section>
              <section id="analysis" className="analysis-card">
                <div className="tabs" role="tablist" aria-label="Mission views">
                  {[
                    ["investigation", "Investigation", findings.length],
                    ["remediation", "Remediation", resolved.size],
                    ["evidence", "Agent activity", mission?.events.length || 0],
                  ].map(([key, title, count]) => (
                    <button
                      key={key}
                      id={`tab-${key}`}
                      role="tab"
                      aria-selected={tab === key}
                      aria-controls={`panel-${key}`}
                      className={tab === key ? "selected" : ""}
                      onClick={() => setTab(key)}
                    >
                      {title}
                      <span>{count}</span>
                    </button>
                  ))}
                  <span className="tabs-note">
                    {running ? "Mission in progress" : "Evidence-led decisions"}
                  </span>
                </div>
                <div
                  role="tabpanel"
                  id={`panel-${tab}`}
                  aria-labelledby={`tab-${tab}`}
                >
                  {tab === "investigation" && (
                    <>
                      <div className="section-toolbar">
                        <div>
                          <h3>Findings & priorities</h3>
                          <p>
                            Select a finding to inspect its evidence and
                            remediation.
                          </p>
                        </div>
                        <select
                          aria-label="Filter findings"
                          value={filter}
                          onChange={(e) => {
                            setFilter(e.target.value);
                            setSelected(null);
                          }}
                        >
                          <option value="ALL">All findings</option>
                          <option value="CRITICAL">Critical</option>
                          <option value="HIGH">High</option>
                          <option value="MEDIUM">Medium</option>
                          <option value="LOW">Low</option>
                          <option value="RESOLVED">Resolved by patch</option>
                        </select>
                      </div>
                      {!findings.length ? (
                        <div className="empty-state">
                          <Icon name={running ? "pulse" : "shield"} size={32} />
                          <h3>
                            {running
                              ? "Collecting and analyzing evidence…"
                              : "No findings from the selected checks"}
                          </h3>
                          <p>
                            {running
                              ? "The mission timeline records each tool action."
                              : "Review coverage and errors before interpreting this result."}
                          </p>
                        </div>
                      ) : (
                        <div className="findings-grid">
                          <div className="finding-list">
                            {visible.length ? (
                              visible.map((f) => (
                                <button
                                  key={f.id}
                                  className={`finding-row ${detail?.id === f.id ? "selected" : ""}`}
                                  onClick={() => setSelected(f.id)}
                                >
                                  <span
                                    className={`severity ${f.severity.toLowerCase()}`}
                                  >
                                    {f.severity}
                                  </span>
                                  <strong>{f.title}</strong>
                                  <span className="finding-location">
                                    {f.resource || f.file}
                                  </span>
                                  <span
                                    className={
                                      resolved.has(f.id)
                                        ? "resolved-label"
                                        : "review-label"
                                    }
                                  >
                                    {resolved.has(f.id)
                                      ? "✓ Proposed fix verified"
                                      : "Needs review"}
                                  </span>
                                </button>
                              ))
                            ) : (
                              <div className="empty-state">
                                No findings match this filter.
                              </div>
                            )}
                          </div>
                          {detail && (
                            <aside className="finding-detail">
                              <span className="eyebrow">
                                EVIDENCE / {detail.rule}
                              </span>
                              <h3>{detail.title}</h3>
                              <code className="file-path">
                                {detail.file}
                                {detail.line ? `:${detail.line}` : ""}
                              </code>
                              <h4>What we observed</h4>
                              <p>{detail.evidence}</p>
                              <h4>Recommended action</h4>
                              <p>{detail.recommendation}</p>
                              <div
                                className={`detail-callout ${resolved.has(detail.id) ? "success" : ""}`}
                              >
                                <Icon
                                  name={
                                    resolved.has(detail.id) ? "check" : "shield"
                                  }
                                  size={18}
                                />
                                <span>
                                  {resolved.has(detail.id)
                                    ? "The candidate patch resolves this rule. Review compatibility before applying."
                                    : detail.fixable
                                      ? "An approved transformation is available for this finding."
                                      : "Manual remediation: application context or a supported transformation is required."}
                                </span>
                              </div>
                            </aside>
                          )}
                        </div>
                      )}
                      {!!mission?.exposure_paths?.length && (
                        <div className="exposure-section">
                          <div className="section-toolbar">
                            <div>
                              <h3>Potential exposure paths</h3>
                              <p>
                                Configuration-based scenarios, not confirmed
                                attacks.
                              </p>
                            </div>
                            <span className="tag-outline">THREAT CONTEXT</span>
                          </div>
                          {mission.exposure_paths.map((path, i) => (
                            <div className="exposure-path" key={i}>
                              <div className="path-nodes">
                                {path.title.split(" → ").map((node, j) => (
                                  <span key={node}>
                                    {j > 0 && <Icon name="arrow" size={15} />}
                                    <span
                                      className={
                                        j === 0
                                          ? "path-node origin"
                                          : "path-node"
                                      }
                                    >
                                      {node}
                                    </span>
                                  </span>
                                ))}
                              </div>
                              <p>{path.description}</p>
                            </div>
                          ))}
                        </div>
                      )}
                    </>
                  )}
                  {tab === "remediation" && (
                    <div className="remediation">
                      <div className="section-toolbar">
                        <div>
                          <h3>Review the proposed change</h3>
                          <p>
                            Changes are staged in an isolated copy. Your
                            repository and AWS resources are untouched.
                          </p>
                        </div>
                        {mission?.verification && (
                          <span
                            className={`status-pill ${mission.verification.passed ? "approved" : "failed"}`}
                          >
                            {mission.verification.passed
                              ? "Static verification passed"
                              : "Verification incomplete"}
                          </span>
                        )}
                      </div>
                      {mission?.patch ? (
                        <>
                          <div className="patch-summary">
                            <Icon name="code" />
                            <p>
                              <strong>{resolved.size} findings resolved</strong>{" "}
                              · {mission.after.total} remaining. Removing public
                              admin ingress can interrupt access; S3 controls
                              can affect public websites. Validate these changes
                              with your team.
                            </p>
                          </div>
                          <pre className="diff" aria-label="Proposed patch">
                            {mission.patch.split("\n").map((line, i) => (
                              <span
                                key={i}
                                className={
                                  line.startsWith("+")
                                    ? "addition"
                                    : line.startsWith("-")
                                      ? "deletion"
                                      : line.startsWith("@@")
                                        ? "hunk"
                                        : ""
                                }
                              >
                                {line || " "}
                                <br />
                              </span>
                            ))}
                          </pre>
                          <div className="approval-bar">
                            <div>
                              <code>
                                SHA-256 {mission.patch_sha256.slice(0, 16)}…
                              </code>
                              {mission.status !== "approved" && (
                                <label className="review-check">
                                  <input
                                    type="checkbox"
                                    checked={reviewed}
                                    onChange={(e) =>
                                      setReviewed(e.target.checked)
                                    }
                                  />{" "}
                                  I reviewed the patch and its operational
                                  impact.
                                </label>
                              )}
                              {mission.status === "approved" && (
                                <p className="resolved-label">
                                  Approved for export. Apply through your normal
                                  code review.
                                </p>
                              )}
                            </div>
                            {mission.status === "approved" ? (
                              <button
                                className="button primary"
                                onClick={() => download("patch")}
                              >
                                <Icon name="download" size={17} /> Download
                                patch
                              </button>
                            ) : (
                              <button
                                className="button primary"
                                disabled={
                                  !reviewed ||
                                  busy ||
                                  mission.status !== "awaiting_approval"
                                }
                                onClick={approve}
                              >
                                <Icon name="check" size={17} /> Approve patch
                              </button>
                            )}
                          </div>
                        </>
                      ) : (
                        <div className="empty-state">
                          <Icon name="code" size={32} />
                          <h3>
                            {running
                              ? "Preparing a remediation plan…"
                              : "No automated patch available"}
                          </h3>
                          <p>
                            Manual findings remain visible in the investigation.
                            Unsupported changes are not generated.
                          </p>
                        </div>
                      )}
                    </div>
                  )}
                  {tab === "evidence" && (
                    <div className="evidence-grid">
                      <div className="activity">
                        <h3>Mission timeline</h3>
                        <p className="muted">
                          Observable tool actions and results.
                        </p>
                        <ol>
                          {mission?.events.map((event) => (
                            <li key={event.sequence}>
                              <span className="event-number">
                                {event.sequence.toString().padStart(2, "0")}
                              </span>
                              <div>
                                <span className="tool-name">
                                  {event.tool.replaceAll("_", " ")}
                                </span>
                                <p>{event.message}</p>
                                <time>
                                  {new Date(event.at).toLocaleTimeString()}
                                </time>
                              </div>
                            </li>
                          ))}
                        </ol>
                      </div>
                      <aside className="coverage">
                        <h3>Scope & provenance</h3>
                        <dl>
                          <dt>Planner</dt>
                          <dd>
                            {mission?.planner === "ai"
                              ? "AI with constrained tools"
                              : "Deterministic policy engine"}
                          </dd>
                          <dt>Files inspected</dt>
                          <dd>{mission?.coverage?.files ?? "Pending"}</dd>
                          <dt>CloudFormation templates</dt>
                          <dd>
                            {mission?.coverage?.cloudformation_templates ??
                              "Pending"}
                          </dd>
                          <dt>Source snapshot</dt>
                          <dd className="hash">
                            {mission?.source_digest || "Pending"}
                          </dd>
                        </dl>
                        <h4>Checks performed</h4>
                        <ul>
                          {mission?.coverage?.checks.map((check) => (
                            <li key={check}>
                              <Icon name="check" size={14} />
                              {check}
                            </li>
                          ))}
                        </ul>
                        <h4>Not evaluated in this mission</h4>
                        <ul>
                          {mission?.coverage?.not_run.map((check) => (
                            <li key={check}>{check}</li>
                          ))}
                        </ul>
                        {!!mission?.errors?.length && (
                          <div className="coverage-errors">
                            <h4>Analysis gaps</h4>
                            {mission.errors.map((e, i) => (
                              <p key={i}>
                                {e.file}: {e.message}
                              </p>
                            ))}
                          </div>
                        )}
                        <p className="coverage-note">
                          Risk points use severity weights: critical 40, high
                          25, medium 10, low 3. They are a prioritization
                          heuristic, not CVSS or a compliance certification.
                        </p>
                      </aside>
                    </div>
                  )}
                </div>
              </section>
            </>
          )}
          <footer className="page-footer">
            <span>
              <Icon size={14} /> CloudGuard · Secure code to cloud
            </span>
            <span>Human-approved changes. Traceable evidence.</span>
          </footer>
        </main>
      </div>
    </div>
  );
}

function Metric({ label, value, suffix, detail, accent }) {
  return (
    <div className={`metric ${accent ? "accent" : ""}`}>
      <p>{label}</p>
      <strong>
        {value}
        <small>{suffix}</small>
      </strong>
      <span>{detail}</span>
    </div>
  );
}

export default App;
