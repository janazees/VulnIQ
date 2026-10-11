
import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  BrainCircuit,
  ChevronDown,
  ChevronRight,
  CircleHelp,
  FileSearch,
  Filter,
  Gauge,
  LayoutDashboard,
  Moon,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Sun,
  Target,
  X,
} from "lucide-react";

import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import "./App.css";

/* ---------- Configuration ---------- */

const THEME_KEY = "vulniq-theme";
const API_BASE = "http://127.0.0.1:8000";

const chartPalettes = {
  dark: {
    severity: ["#fb7185", "#f59e0b", "#a78bfa", "#38bdf8"],
    grid: "#292737",
    tick: "#8e8aa2",
    tickStrong: "#c9c5d9",
    bar: "#9b83f6",
    positive: "#a78bfa",
    negative: "#38bdf8",
    tooltipBg: "#171622",
    tooltipBorder: "#343144",
    tooltipText: "#ffffff",
  },
  light: {
    severity: ["#e11d48", "#d97706", "#7c5cf0", "#0284c7"],
    grid: "#e4e1f2",
    tick: "#6b6785",
    tickStrong: "#2c2945",
    bar: "#6d4fe0",
    positive: "#6d4fe0",
    negative: "#0284c7",
    tooltipBg: "#ffffff",
    tooltipBorder: "#d9d5ec",
    tooltipText: "#1c1a2e",
  },
};

/* ---------- Illustrative chart data ---------- */

const trendData = [
  { month: "May", count: 184 },
  { month: "Jun", count: 232 },
  { month: "Jul", count: 207 },
  { month: "Aug", count: 289 },
  { month: "Sep", count: 254 },
  { month: "Oct", count: 318 },
];

const demoExplanations = [
  { feature: "Attack vector: Network", impact: 0.92 },
  { feature: "Exploitability score", impact: 0.76 },
  { feature: "Privileges required: None", impact: 0.63 },
  { feature: "EPSS probability", impact: 0.49 },
  { feature: "User interaction required", impact: -0.24 },
];

/* ---------- Helpers ---------- */

const getInitialTheme = () => {
  try {
    const saved = localStorage.getItem(THEME_KEY);
    if (saved === "light" || saved === "dark") return saved;
  } catch {
    // Storage may be unavailable.
  }

  return window.matchMedia?.("(prefers-color-scheme: light)").matches
    ? "light"
    : "dark";
};

const formatNumber = (number) =>
  new Intl.NumberFormat("en-US").format(Number(number) || 0);

const formatPercent = (value) =>
  `${((Number(value) || 0) * 100).toFixed(1)}%`;

/* This is a temporary heuristic, not the trained model prediction. */
function mapApiRecord(row) {
  const score =
    row.base_score == null || row.base_score === ""
      ? null
      : Number(row.base_score);

  const epss =
    row.epss_score == null || row.epss_score === ""
      ? null
      : Number(row.epss_score);

  const kevValue = String(row.cisa_kev ?? "").trim().toLowerCase();
  const isKev = ["true", "1", "yes"].includes(kevValue);

  const safeScore = Number.isFinite(score) ? score : 0;
  const safeEpss = Number.isFinite(epss) ? epss : 0;

  const priority = Math.min(
    100,
    Math.round(safeScore * 4 + safeEpss * 40 + (isKev ? 20 : 0))
  );

  const description = row.description || "No description available";

  return {
    id: row.cve_id || "Unknown CVE",
    title:
      description.length > 100
        ? `${description.slice(0, 100)}...`
        : description,
    severity: String(row.base_severity || "NONE").toUpperCase(),
    score: Number.isFinite(score) ? score : null,
    vector: String(row.attack_vector || "UNKNOWN").toUpperCase(),
    epss: Number.isFinite(epss) ? epss : null,
    status: isKev ? "In CISA KEV" : "Not listed in KEV",
    date: row.published_date || "Unknown",
    description,
    priority,
    tier: priority >= 90 ? "P1" : priority >= 70 ? "P2" : "P3",
    rank: 0,
  };
}

/* ---------- Small components ---------- */

function SeverityBadge({ severity }) {
  const safeSeverity = String(severity || "NONE").toUpperCase();

  return (
    <span className={`severity-badge ${safeSeverity.toLowerCase()}`}>
      <span className="severity-dot" />
      {safeSeverity}
    </span>
  );
}

function PriorityCell({ priority, tier }) {
  return (
    <div className="priority-cell">
      <span className={`tier-badge ${tier.toLowerCase()}`}>{tier}</span>
      <div
        className="priority-bar"
        role="img"
        aria-label={`Heuristic priority score ${priority} out of 100`}
      >
        <span style={{ width: `${priority}%` }} />
      </div>
      <strong>{priority}</strong>
    </div>
  );
}

function StatCard({ icon: Icon, label, value, change, tone, note }) {
  return (
    <article className="stat-card">
      <div className="stat-card-top">
        <span className={`stat-icon ${tone}`}>
          <Icon size={19} />
        </span>
        <span className="stat-note">{note}</span>
      </div>

      <p className="stat-label">{label}</p>

      <div className="stat-value-row">
        <h2>{value}</h2>
        {change && (
          <span className="stat-change">
            <ArrowUpRight size={14} />
            {change}
          </span>
        )}
      </div>
    </article>
  );
}

function ThemeToggle({ theme, onToggle }) {
  const next = theme === "dark" ? "light" : "dark";

  return (
    <button
      className="theme-toggle"
      onClick={onToggle}
      aria-label={`Switch to ${next} theme`}
      title={`Switch to ${next} theme`}
    >
      {theme === "dark" ? <Sun size={17} /> : <Moon size={17} />}
    </button>
  );
}

/* ---------- App ---------- */

function App() {
  const [theme, setTheme] = useState(getInitialTheme);
  const [activeTab, setActiveTab] = useState("Overview");

  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("ALL");

  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [stats, setStats] = useState(null);
  const [totalMatches, setTotalMatches] = useState(0);

  const [loading, setLoading] = useState(true);
  const [statsError, setStatsError] = useState("");
  const [apiError, setApiError] = useState("");

  const [selectedCve, setSelectedCve] = useState(null);
  const [showDetails, setShowDetails] = useState(false);

  // Trained model prediction state
  const [modelPrediction, setModelPrediction] = useState(null);
  const [predictionLoading, setPredictionLoading] = useState(false);
  const [predictionError, setPredictionError] = useState("");

  const colors = chartPalettes[theme];

  /* ---------- Theme ---------- */

  useEffect(() => {
    document.documentElement.dataset.theme = theme;

    try {
      localStorage.setItem(THEME_KEY, theme);
    } catch {
      // Ignore storage errors.
    }
  }, [theme]);

  const toggleTheme = () => {
    setTheme((current) => (current === "dark" ? "light" : "dark"));
  };

  /* ---------- Fetch dataset statistics ---------- */

  useEffect(() => {
    const controller = new AbortController();

    async function loadStats() {
      try {
        const response = await fetch(`${API_BASE}/api/stats`, {
          signal: controller.signal,
        });

        if (!response.ok) {
          throw new Error(`Statistics request failed (${response.status})`);
        }

        const data = await response.json();
        setStats(data);
        setStatsError("");
      } catch (error) {
        if (error.name !== "AbortError") {
          setStatsError(
            "Could not load dataset statistics. Check that the backend is running."
          );
        }
      }
    }

    loadStats();

    return () => controller.abort();
  }, []);

  /* ---------- Fetch vulnerability records ---------- */

  useEffect(() => {
    const controller = new AbortController();

    const timer = window.setTimeout(async () => {
      setLoading(true);
      setApiError("");

      try {
        const params = new URLSearchParams({
          q: search.trim(),
          severity: severityFilter,
          limit: "100",
          offset: "0",
        });

        const response = await fetch(
          `${API_BASE}/api/vulnerabilities?${params.toString()}`,
          { signal: controller.signal }
        );

        if (!response.ok) {
          throw new Error(
            `Vulnerability request failed (${response.status})`
          );
        }

        const data = await response.json();

        const rows = (data.items || [])
          .map(mapApiRecord)
          .sort((a, b) => b.priority - a.priority)
          .map((cve, index) => ({
            ...cve,
            rank: index + 1,
          }));

        setVulnerabilities(rows);
        setTotalMatches(Number(data.total) || 0);
      } catch (error) {
        if (error.name !== "AbortError") {
          setApiError(
            "Could not load vulnerability records. Check the backend and API connection."
          );
          setVulnerabilities([]);
          setTotalMatches(0);
        }
      } finally {
        if (!controller.signal.aborted) {
          setLoading(false);
        }
      }
    }, 250);

    return () => {
      window.clearTimeout(timer);
      controller.abort();
    };
  }, [search, severityFilter]);

  /* ---------- Fetch trained model prediction ---------- */

  useEffect(() => {
    if (!showDetails || !selectedCve?.id) return;

    const controller = new AbortController();

    async function loadPrediction() {
      setPredictionLoading(true);
      setPredictionError("");
      setModelPrediction(null);

      try {
        const response = await fetch(
          `${API_BASE}/api/predict/${encodeURIComponent(selectedCve.id)}`,
          { signal: controller.signal }
        );

        if (!response.ok) {
          throw new Error(`Prediction request failed (${response.status})`);
        }

        const data = await response.json();
        setModelPrediction(data);
      } catch (error) {
        if (error.name !== "AbortError") {
          setPredictionError(
            responseErrorMessage(error)
          );
        }
      } finally {
        if (!controller.signal.aborted) {
          setPredictionLoading(false);
        }
      }
    }

    loadPrediction();

    return () => controller.abort();
  }, [showDetails, selectedCve?.id]);

  /* ---------- Chart data ---------- */

  const severityOrder = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

  const severityData = severityOrder.map((severity, index) => ({
    name: severity.charAt(0) + severity.slice(1).toLowerCase(),
    value: Number(stats?.severity_counts?.[severity] ?? 0),
    color: colors.severity[index],
  }));

  const filteredVulnerabilities = useMemo(
    () => vulnerabilities,
    [vulnerabilities]
  );

  const tooltipStyle = {
    background: colors.tooltipBg,
    border: `1px solid ${colors.tooltipBorder}`,
    borderRadius: "10px",
    color: colors.tooltipText,
  };

  /* ---------- Navigation ---------- */

  const openCve = (cve) => {
    setSelectedCve(cve);
    setModelPrediction(null);
    setPredictionError("");
    setShowDetails(true);
    setActiveTab("Vulnerabilities");
  };

  const navigateTo = (tab) => {
    setActiveTab(tab);
    setSeverityFilter("ALL");
    setSearch("");
  };

  /* ---------- Render ---------- */

  return (
    <div className="app-shell">
      <header className="topbar">
        <a
          className="brand"
          href="#overview"
          onClick={() => navigateTo("Overview")}
        >
          <span className="brand-mark">
            <Shield size={23} strokeWidth={2.2} />
          </span>
          <span className="brand-copy">
            <strong>
              Vuln<span>IQ</span>
            </strong>
            <small>EXPLAINABLE SECURITY</small>
          </span>
        </a>

        <nav className="main-nav" aria-label="Main navigation">
          {[
            { label: "Overview", icon: LayoutDashboard },
            { label: "Vulnerabilities", icon: FileSearch },
            { label: "Explainability", icon: BrainCircuit },
          ].map(({ label, icon: Icon }) => (
            <button
              key={label}
              className={`nav-link ${activeTab === label ? "active" : ""}`}
              onClick={() => navigateTo(label)}
            >
              <Icon size={16} />
              {label}
            </button>
          ))}
        </nav>

        <div className="topbar-right">
          <span className="environment-pill">
            <span className="live-dot" />
            API CONNECTED
          </span>
          <ThemeToggle theme={theme} onToggle={toggleTheme} />
          <div className="avatar">VI</div>
        </div>
      </header>

      <main className="main-content">
        <div className="demo-banner">
          <CircleHelp size={16} />
          <span>
            <strong>Live dataset and model</strong> — CVE records and
            statistics come from your local API. The trained model estimates
            CISA KEV inclusion in each CVE detail view. Priority scores,
            activity trends, and SHAP-style explanations remain illustrative.
          </span>
        </div>

        <section className="page-heading">
          <div>
            <div className="eyebrow">
              <span className="eyebrow-line" />
              SECURITY INTELLIGENCE
            </div>

            <h1>
              {activeTab === "Overview"
                ? "Vulnerability overview"
                : activeTab === "Vulnerabilities"
                  ? "Prioritized CVE list"
                  : "AI explainability"}
            </h1>

            <p className="page-description">
              {activeTab === "Overview"
                ? "Monitor vulnerability exposure and understand security risk."
                : activeTab === "Vulnerabilities"
                  ? "Explore vulnerability records, heuristic priorities, and trained model predictions."
                  : "Explore illustrative feature contributions. Actual SHAP explanations are not yet connected."}
            </p>
          </div>

          <button
            className="date-button"
            onClick={() =>
              window.alert(
                "Date filtering will be added after publication-date filtering is implemented."
              )
            }
          >
            <Activity size={16} />
            All dataset dates
            <ChevronDown size={15} />
          </button>
        </section>

        {/* ---------- Overview ---------- */}

        {activeTab === "Overview" && (
          <>
            {statsError && (
              <div className="empty-state">
                <strong>Statistics unavailable</strong>
                <p>{statsError}</p>
              </div>
            )}

            <section className="stats-grid">
              <StatCard
                icon={ShieldAlert}
                label="Total CVE records"
                value={stats ? formatNumber(stats.total_records) : "..."}
                change="Dataset"
                tone="violet"
                note="CSV"
              />

              <StatCard
                icon={AlertTriangle}
                label="Critical vulnerabilities"
                value={
                  stats
                    ? formatNumber(stats.severity_counts?.CRITICAL ?? 0)
                    : "..."
                }
                tone="red"
                note="Severity"
              />

              <StatCard
                icon={Target}
                label="High severity"
                value={
                  stats
                    ? formatNumber(stats.severity_counts?.HIGH ?? 0)
                    : "..."
                }
                tone="amber"
                note="Severity"
              />

              <StatCard
                icon={ShieldCheck}
                label="Duplicate records"
                value={
                  stats ? formatNumber(stats.duplicate_rows ?? 0) : "..."
                }
                tone="green"
                note="Checked"
              />
            </section>

            <section className="charts-grid">
              <article className="panel severity-panel">
                <div className="panel-heading">
                  <div>
                    <h3>Severity distribution</h3>
                    <p>Breakdown across the CVE dataset</p>
                  </div>
                  <span className="panel-icon">
                    <Gauge size={18} />
                  </span>
                </div>

                <div className="severity-chart-wrap">
                  <div className="donut-chart">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={severityData}
                          dataKey="value"
                          nameKey="name"
                          innerRadius="68%"
                          outerRadius="92%"
                          paddingAngle={3}
                          stroke="none"
                        >
                          {severityData.map((entry) => (
                            <Cell key={entry.name} fill={entry.color} />
                          ))}
                        </Pie>
                        <Tooltip
                          formatter={(value) => formatNumber(value)}
                          contentStyle={tooltipStyle}
                          itemStyle={{ color: colors.tooltipText }}
                        />
                      </PieChart>
                    </ResponsiveContainer>

                    <div className="donut-center">
                      <strong>
                        {stats
                          ? `${(stats.total_records / 1000).toFixed(1)}K`
                          : "..."}
                      </strong>
                      <span>Total CVEs</span>
                    </div>
                  </div>

                  <div className="severity-legend">
                    {severityData.map((item) => (
                      <button
                        key={item.name}
                        className="legend-row"
                        onClick={() => {
                          setSeverityFilter(item.name.toUpperCase());
                          setSearch("");
                          setActiveTab("Vulnerabilities");
                        }}
                      >
                        <span
                          className="legend-dot"
                          style={{ background: item.color }}
                        />
                        <span className="legend-name">{item.name}</span>
                        <strong>{formatNumber(item.value)}</strong>
                      </button>
                    ))}
                  </div>
                </div>

                <p className="chart-footnote">
                  Counts come from the backend dataset summary. NONE severity
                  is omitted from this chart.
                </p>
              </article>

              <article className="panel trend-panel">
                <div className="panel-heading">
                  <div>
                    <h3>Detection activity</h3>
                    <p>Illustrative monthly activity</p>
                  </div>
                  <span className="trend-indicator">
                    <ArrowUpRight size={14} /> Demo trend
                  </span>
                </div>

                <div className="trend-chart">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart
                      data={trendData}
                      margin={{ top: 15, right: 5, left: -22, bottom: 0 }}
                    >
                      <CartesianGrid
                        stroke={colors.grid}
                        strokeDasharray="3 3"
                        vertical={false}
                      />
                      <XAxis
                        dataKey="month"
                        axisLine={false}
                        tickLine={false}
                        tick={{ fill: colors.tick, fontSize: 12 }}
                      />
                      <YAxis
                        axisLine={false}
                        tickLine={false}
                        tick={{ fill: colors.tick, fontSize: 12 }}
                      />
                      <Tooltip
                        cursor={{ fill: colors.bar, fillOpacity: 0.08 }}
                        contentStyle={tooltipStyle}
                        itemStyle={{ color: colors.tooltipText }}
                        labelStyle={{ color: colors.tooltipText }}
                      />
                      <Bar
                        dataKey="count"
                        name="Demo activity"
                        fill={colors.bar}
                        radius={[5, 5, 0, 0]}
                        maxBarSize={34}
                      />
                    </BarChart>
                  </ResponsiveContainer>
                </div>

                <p className="chart-footnote">
                  These values are placeholders, not real publication-date
                  statistics.
                </p>
              </article>
            </section>

            <section className="panel table-panel">
              <div className="panel-heading table-panel-heading">
                <div>
                  <h3>Top priorities</h3>
                  <p>Highest heuristic priority scores in the loaded records</p>
                </div>
                <button
                  className="text-button"
                  onClick={() => navigateTo("Vulnerabilities")}
                >
                  View all <ChevronRight size={16} />
                </button>
              </div>

              {apiError ? (
                <div className="empty-state">
                  <strong>Unable to load vulnerability records</strong>
                  <p>{apiError}</p>
                </div>
              ) : loading ? (
                <p className="chart-footnote">Loading CVE records...</p>
              ) : (
                <VulnerabilityTable
                  rows={vulnerabilities.slice(0, 4)}
                  onSelect={openCve}
                />
              )}
            </section>
          </>
        )}

        {/* ---------- Vulnerability explorer ---------- */}

        {activeTab === "Vulnerabilities" && (
          <section className="panel explorer-panel">
            <div className="panel-heading explorer-heading">
              <div>
                <h3>Priority ranking</h3>
                <p>
                  {loading
                    ? "Loading vulnerability records..."
                    : `Showing ${formatNumber(
                        vulnerabilities.length
                      )} of ${formatNumber(totalMatches)} matching records`}
                </p>
              </div>
              <span className="demo-chip">LIVE DATASET</span>
            </div>

            <div className="filter-row">
              <div className="search-box">
                <Search size={17} />
                <input
                  type="search"
                  value={search}
                  onChange={(event) => setSearch(event.target.value)}
                  placeholder="Search CVE ID, description, or severity..."
                  aria-label="Search vulnerability records"
                />
                {search && (
                  <button
                    className="clear-search"
                    onClick={() => setSearch("")}
                    aria-label="Clear search"
                  >
                    <X size={15} />
                  </button>
                )}
              </div>

              <div className="filter-select-wrap">
                <Filter size={16} />
                <select
                  value={severityFilter}
                  onChange={(event) => setSeverityFilter(event.target.value)}
                  aria-label="Filter by severity"
                >
                  <option value="ALL">All severities</option>
                  <option value="CRITICAL">Critical</option>
                  <option value="HIGH">High</option>
                  <option value="MEDIUM">Medium</option>
                  <option value="LOW">Low</option>
                  <option value="NONE">None</option>
                </select>
              </div>
            </div>

            {apiError && (
              <div className="empty-state">
                <strong>Unable to load live data</strong>
                <p>{apiError}</p>
              </div>
            )}

            {loading && (
              <p className="chart-footnote">Loading CVE records...</p>
            )}

            {!loading && !apiError && vulnerabilities.length > 0 && (
              <VulnerabilityTable
                rows={filteredVulnerabilities}
                onSelect={openCve}
              />
            )}

            {!loading && !apiError && vulnerabilities.length === 0 && (
              <div className="empty-state">
                <Search size={28} />
                <strong>No matching CVEs</strong>
                <p>Try a different search term or severity filter.</p>
                <button
                  className="secondary-button"
                  onClick={() => {
                    setSearch("");
                    setSeverityFilter("ALL");
                  }}
                >
                  Clear filters
                </button>
              </div>
            )}

            <p className="chart-footnote explorer-note">
              Priority scores use a temporary heuristic based on CVSS, EPSS,
              and CISA KEV membership. The trained model prediction is shown
              separately when you open a CVE. Only the first 100 matching
              records are currently displayed.
            </p>
          </section>
        )}

        {/* ---------- Explainability ---------- */}

        {activeTab === "Explainability" && (
          <section className="explain-grid">
            <article className="panel explain-main">
              <div className="panel-heading">
                <div>
                  <h3>Feature contribution</h3>
                  <p>Illustrative SHAP-style explanation</p>
                </div>
                <span className="panel-icon">
                  <BrainCircuit size={18} />
                </span>
              </div>

              <div className="explain-callout">
                <Sparkles size={19} />
                <div>
                  <strong>Understanding model explanations</strong>
                  <p>
                    Feature contributions can help explain why a model makes
                    a prediction. The chart below is an illustrative example,
                    not a calculation from the trained model.
                  </p>
                </div>
              </div>

              <div className="feature-chart">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart
                    data={demoExplanations}
                    layout="vertical"
                    margin={{ top: 5, right: 20, left: 8, bottom: 5 }}
                  >
                    <CartesianGrid
                      stroke={colors.grid}
                      strokeDasharray="3 3"
                      horizontal={false}
                    />
                    <XAxis
                      type="number"
                      domain={[-0.4, 1]}
                      axisLine={false}
                      tickLine={false}
                      tick={{ fill: colors.tick, fontSize: 11 }}
                    />
                    <YAxis
                      type="category"
                      dataKey="feature"
                      width={175}
                      axisLine={false}
                      tickLine={false}
                      tick={{ fill: colors.tickStrong, fontSize: 11 }}
                    />
                    <Tooltip
                      contentStyle={tooltipStyle}
                      itemStyle={{ color: colors.tooltipText }}
                      labelStyle={{ color: colors.tooltipText }}
                      formatter={(value) => [
                        Number(value).toFixed(2),
                        "Example contribution",
                      ]}
                    />
                    <Bar dataKey="impact" name="Contribution" radius={4}>
                      {demoExplanations.map((entry) => (
                        <Cell
                          key={entry.feature}
                          fill={
                            entry.impact >= 0
                              ? colors.positive
                              : colors.negative
                          }
                        />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>

              <div className="explanation-legend">
                <span>
                  <i className="positive-dot" /> Pushes risk higher
                </span>
                <span>
                  <i className="negative-dot" /> Pushes risk lower
                </span>
              </div>

              <p className="chart-footnote">
                Illustrative values only. Actual SHAP values have not yet been
                connected to the trained model.
              </p>
            </article>

            <article className="panel explain-side">
              <div className="panel-heading">
                <div>
                  <h3>Explanation guide</h3>
                  <p>How to read the chart</p>
                </div>
              </div>

              <div className="guide-item">
                <span className="guide-number">01</span>
                <div>
                  <strong>Feature importance</strong>
                  <p>
                    Shows which input features have the largest effect on a
                    particular model prediction.
                  </p>
                </div>
              </div>

              <div className="guide-item">
                <span className="guide-number">02</span>
                <div>
                  <strong>Positive contribution</strong>
                  <p>
                    A feature may push the model output toward the explained
                    class. Its meaning depends on the model and target.
                  </p>
                </div>
              </div>

              <div className="guide-item">
                <span className="guide-number">03</span>
                <div>
                  <strong>Negative contribution</strong>
                  <p>
                    A feature may push the output away from the explained
                    class. It does not prove a vulnerability is safe.
                  </p>
                </div>
              </div>

              <div className="method-note">
                <BrainCircuit size={18} />
                <div>
                  <strong>Method: SHAP</strong>
                  <p>
                    This section is illustrative; it does not yet show SHAP
                    values calculated from the trained model.
                  </p>
                </div>
              </div>
            </article>
          </section>
        )}

        <footer className="footer">
          <span>
            <span className="footer-mark">◆</span> VulnIQ
            <span className="footer-divider">/</span>
            CVE Explainable AI
          </span>
          <span>Research prototype · Local API</span>
        </footer>
      </main>

      {/* ---------- CVE details modal ---------- */}

      {showDetails && selectedCve && (
        <div
          className="modal-backdrop"
          role="presentation"
          onClick={() => setShowDetails(false)}
        >
          <section
            className="detail-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="detail-title"
            onClick={(event) => event.stopPropagation()}
          >
            <div className="modal-header">
              <div className="modal-icon">
                <ShieldAlert size={22} />
              </div>
              <button
                className="icon-button"
                onClick={() => setShowDetails(false)}
                aria-label="Close details"
              >
                <X size={19} />
              </button>
            </div>

            <span className="modal-eyebrow">
              LIVE CVE RECORD · RANK #{selectedCve.rank}
            </span>

            <h2 id="detail-title">{selectedCve.id}</h2>
            <p className="modal-description">{selectedCve.title}</p>

            <div className="modal-score-row">
              <div className="modal-score">
                <span>CVSS score</span>
                <strong>
                  {selectedCve.score == null
                    ? "N/A"
                    : selectedCve.score.toFixed(1)}
                </strong>
                <SeverityBadge severity={selectedCve.severity} />
              </div>

              <div className="modal-metric">
                <span>Heuristic priority</span>
                <strong>{selectedCve.priority}</strong>
                <span
                  className={`tier-badge ${selectedCve.tier.toLowerCase()}`}
                >
                  {selectedCve.tier}
                </span>
              </div>

              <div className="modal-metric">
                <span>EPSS</span>
                <strong>
                  {selectedCve.epss == null
                    ? "N/A"
                    : formatPercent(selectedCve.epss)}
                </strong>
              </div>
            </div>

            {/* Trained model prediction */}

            <div className="modal-section">
              <h4>
                <BrainCircuit
                  size={17}
                  style={{
                    display: "inline",
                    verticalAlign: "middle",
                    marginRight: "8px",
                  }}
                />
                AI Model Prediction
              </h4>

              {predictionLoading ? (
                <p>Running trained model...</p>
              ) : predictionError ? (
                <p role="alert">{predictionError}</p>
              ) : modelPrediction ? (
                <>
                  <div className="modal-info-row">
                    <span>Predicted CISA KEV inclusion</span>
                    <strong>
                      {modelPrediction.predicted_kev ? "Likely" : "Unlikely"}
                    </strong>
                  </div>

                  <div className="modal-info-row">
                    <span>Model-estimated probability</span>
                    <strong>
                      {formatPercent(modelPrediction.kev_probability)}
                    </strong>
                  </div>

                  <p className="chart-footnote">
                    {modelPrediction.interpretation}
                  </p>
                </>
              ) : (
                <p>Prediction not available.</p>
              )}
            </div>

            <div className="modal-section">
              <h4>Description</h4>
              <p>{selectedCve.description}</p>
            </div>

            <div className="modal-section">
              <h4>Record information</h4>
              <div className="modal-info-row">
                <span>Attack vector</span>
                <strong>{selectedCve.vector}</strong>
              </div>
              <div className="modal-info-row">
                <span>Published date</span>
                <strong>{selectedCve.date}</strong>
              </div>
              <div className="modal-info-row">
                <span>CISA KEV status in dataset</span>
                <strong>{selectedCve.status}</strong>
              </div>
            </div>

            <div className="modal-disclaimer">
              <AlertTriangle size={16} />
              The model estimates CISA KEV inclusion; it is not a CVSS score
              or a guarantee of exploitation. The priority score is a separate
              heuristic. Verify findings against authoritative vulnerability
              sources.
            </div>

            <button
              className="primary-button modal-action"
              onClick={() => {
                setShowDetails(false);
                setActiveTab("Explainability");
              }}
            >
              <BrainCircuit size={16} />
              View example explanation
            </button>
          </section>
        </div>
      )}
    </div>
  );
}

/* ---------- Prediction error helper ---------- */

function responseErrorMessage() {
  return "Could not generate a model prediction. Check that the backend is running and this CVE exists in its dataset.";
}

/* ---------- Vulnerability table ---------- */

function VulnerabilityTable({ rows, onSelect }) {
  return (
    <div className="table-scroll">
      <table className="vulnerability-table">
        <thead>
          <tr>
            <th>RANK</th>
            <th>CVE / VULNERABILITY</th>
            <th>SEVERITY</th>
            <th>CVSS</th>
            <th>EPSS</th>
            <th>CISA KEV STATUS</th>
            <th>PRIORITY</th>
            <th aria-label="Actions" />
          </tr>
        </thead>

        <tbody>
          {rows.map((cve) => (
            <tr
              key={cve.id}
              className="clickable-row"
              onClick={() => onSelect(cve)}
            >
              <td>
                <span className="rank-cell">#{cve.rank}</span>
              </td>

              <td>
                <div className="cve-cell">
                  <strong>{cve.id}</strong>
                  <span>{cve.title}</span>
                </div>
              </td>

              <td>
                <SeverityBadge severity={cve.severity} />
              </td>

              <td>
                <span className="score-cell">
                  {cve.score == null ? "N/A" : cve.score.toFixed(1)}
                </span>
              </td>

              <td>
                <strong className="epss-text">
                  {cve.epss == null ? "N/A" : formatPercent(cve.epss)}
                </strong>
              </td>

              <td>
                <span
                  className={`status-pill ${
                    cve.status === "In CISA KEV" ? "status-danger" : ""
                  }`}
                >
                  {cve.status === "In CISA KEV" && (
                    <span className="status-dot" />
                  )}
                  {cve.status}
                </span>
              </td>

              <td>
                <PriorityCell priority={cve.priority} tier={cve.tier} />
              </td>

              <td>
                <button
                  className="row-action"
                  aria-label={`View ${cve.id}`}
                  onClick={(event) => {
                    event.stopPropagation();
                    onSelect(cve);
                  }}
                >
                  <ChevronRight size={17} />
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default App;
