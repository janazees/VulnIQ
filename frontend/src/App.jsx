import { useEffect, useState } from "react";
import {
  AlertTriangle,
  ArrowUpRight,
  BrainCircuit,
  ChevronRight,
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

const METRIC_LABELS = [
  ["roc_auc", "ROC-AUC"],
  ["pr_auc", "PR-AUC"],
  ["precision", "Precision"],
  ["recall", "Recall"],
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

const toNumberOrNull = (value) => {
  if (value == null || value === "") return null;
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
};

const formatNumber = (number) =>
  new Intl.NumberFormat("en-US").format(Number(number) || 0);

const formatPercent = (value) =>
  `${((Number(value) || 0) * 100).toFixed(1)}%`;

const formatProbability = (value) => {
  if (value == null) return "N/A";

  const percent = value * 100;

  return percent > 0 && percent < 0.1
    ? "<0.1%"
    : `${percent.toFixed(1)}%`;
};

/* Maps one API row. modelScore is the trained model's KEV probability. */

function mapApiRecord(row, index) {
  const score = toNumberOrNull(row.base_score);
  const epss = toNumberOrNull(row.epss_score);
  const modelScore = toNumberOrNull(row.kev_probability);

  const kevValue = String(row.cisa_kev ?? "").trim().toLowerCase();
  const isKev = ["true", "1", "yes"].includes(kevValue);

  const description = row.description || "No description available";

  return {
    id: row.cve_id || "Unknown CVE",
    title:
      description.length > 100
        ? `${description.slice(0, 100)}...`
        : description,
    severity: String(row.base_severity || "NONE").toUpperCase(),
    score,
    vector: String(row.attack_vector || "UNKNOWN").toUpperCase(),
    epss,
    status: isKev ? "In CISA KEV" : "Not listed in KEV",
    date: row.published_date || "Unknown",
    description,
    modelScore,
    rank: index + 1,
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

function ModelRiskCell({ value }) {
  if (value == null) {
    return <span className="rank-cell">N/A</span>;
  }

  return (
    <div className="priority-cell">
      <div
        className="priority-bar"
        role="img"
        aria-label={`Model KEV probability ${formatProbability(value)}`}
      >
        <span style={{ width: `${Math.max(2, value * 100)}%` }} />
      </div>
      <strong>{formatProbability(value)}</strong>
    </div>
  );
}

function StatCard({ icon: Icon, label, value, tone, note }) {
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
  const [hideKev, setHideKev] = useState(true);

  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [stats, setStats] = useState(null);
  const [totalMatches, setTotalMatches] = useState(0);

  const [loading, setLoading] = useState(true);
  const [statsError, setStatsError] = useState("");
  const [apiError, setApiError] = useState("");

  const [modelInfo, setModelInfo] = useState(null);
  const [modelInfoError, setModelInfoError] = useState("");

  const [selectedCve, setSelectedCve] = useState(null);
  const [showDetails, setShowDetails] = useState(false);

  const [modelPrediction, setModelPrediction] = useState(null);
  const [predictionLoading, setPredictionLoading] = useState(false);
  const [predictionError, setPredictionError] = useState("");

  /* Live prediction by CVE ID */
  const [liveCveId, setLiveCveId] = useState("CVE-2021-44228");
  const [livePrediction, setLivePrediction] = useState(null);
  const [livePredictionLoading, setLivePredictionLoading] = useState(false);
  const [livePredictionError, setLivePredictionError] = useState("");

  /* SHAP explanation */
  const [shapExplanation, setShapExplanation] = useState(null);
  const [shapLoading, setShapLoading] = useState(false);
  const [shapError, setShapError] = useState("");
  const [shapRetry, setShapRetry] = useState(0);

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

  /* ---------- Dataset statistics ---------- */

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

        setStats(await response.json());
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

  /* ---------- Model details ---------- */

  useEffect(() => {
    const controller = new AbortController();

    async function loadModelInfo() {
      try {
        const response = await fetch(`${API_BASE}/api/model-info`, {
          signal: controller.signal,
        });

        if (!response.ok) {
          throw new Error(`Model info request failed (${response.status})`);
        }

        setModelInfo(await response.json());
        setModelInfoError("");
      } catch (error) {
        if (error.name !== "AbortError") {
          setModelInfoError(
            error.message || "Could not load model details from the backend."
          );
        }
      }
    }

    loadModelInfo();

    return () => controller.abort();
  }, []);

  /* ---------- Vulnerability records ---------- */

  useEffect(() => {
    const controller = new AbortController();

    const timer = window.setTimeout(async () => {
      setLoading(true);
      setApiError("");

      try {
        const params = new URLSearchParams({
          q: search.trim(),
          severity: severityFilter,
          sort: "model",
          exclude_kev: String(hideKev),
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

        setVulnerabilities((data.items || []).map(mapApiRecord));
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
  }, [search, severityFilter, hideKev]);

  /* ---------- Model prediction for selected CVE ---------- */

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
          const errorBody = await response.json().catch(() => null);

          throw new Error(
            errorBody?.detail ||
              `Prediction request failed (${response.status})`
          );
        }

        setModelPrediction(await response.json());
      } catch (error) {
        if (error.name !== "AbortError") {
          setPredictionError(
            error.message ||
              "Could not generate a model prediction. Check that the backend is running and this CVE exists in its dataset."
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

  /* ---------- SHAP explanation ---------- */

  useEffect(() => {
    if (activeTab !== "Explainability" || !selectedCve?.id) return;

    const controller = new AbortController();

    async function loadShapExplanation() {
      setShapLoading(true);
      setShapError("");
      setShapExplanation(null);

      try {
        const response = await fetch(
          `${API_BASE}/api/explain/${encodeURIComponent(selectedCve.id)}`,
          { signal: controller.signal }
        );

        if (!response.ok) {
          const errorBody = await response.json().catch(() => null);

          throw new Error(
            errorBody?.detail ||
              `SHAP explanation request failed (${response.status})`
          );
        }

        const data = await response.json();

        if (!Array.isArray(data.contributions)) {
          throw new Error(
            "The backend response does not contain SHAP contributions."
          );
        }

        const contributions = data.contributions
          .map((item) => ({
            feature: String(item.feature ?? "Unknown feature"),
            impact: Number(item.shap_value),
            direction: String(item.direction ?? "").toLowerCase(),
          }))
          .filter(
            (item) =>
              Number.isFinite(item.impact) && item.feature.trim().length > 0
          );

        if (contributions.length === 0) {
          throw new Error(
            "The backend returned no valid SHAP contributions for this CVE."
          );
        }

        setShapExplanation({ ...data, contributions });
      } catch (error) {
        if (error.name !== "AbortError") {
          setShapError(
            error.message ||
              "Could not load SHAP values. Check the backend logs."
          );
        }
      } finally {
        if (!controller.signal.aborted) {
          setShapLoading(false);
        }
      }
    }

    loadShapExplanation();

    return () => controller.abort();
  }, [activeTab, selectedCve?.id, shapRetry]);

  /* ---------- Derived data ---------- */

  const severityOrder = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

  const severityData = severityOrder.map((severity, index) => ({
    name: severity.charAt(0) + severity.slice(1).toLowerCase(),
    value: Number(stats?.severity_counts?.[severity] ?? 0),
    color: colors.severity[index],
  }));

  const importanceData = (modelInfo?.feature_importance || [])
    .map((item) => ({
      feature: String(item.feature ?? ""),
      importance: Number(item.importance),
    }))
    .filter((item) => item.feature && Number.isFinite(item.importance))
    .slice(0, 8);

  const metricChips = METRIC_LABELS.filter(
    ([key]) => toNumberOrNull(modelInfo?.metrics?.[key]) != null
  ).map(([key, label]) => ({
    label,
    value: Number(modelInfo.metrics[key]).toFixed(3),
  }));

  const scoresMissing =
    !loading &&
    !apiError &&
    vulnerabilities.length > 0 &&
    vulnerabilities.every((cve) => cve.modelScore == null);

  const apiStatus = apiError || statsError
    ? "offline"
    : stats
      ? "online"
      : "connecting";

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
    setShapExplanation(null);
    setShapError("");
    setShowDetails(true);
    setActiveTab("Vulnerabilities");
  };

  /* ---------- Live prediction by CVE ID ---------- */

  const runLivePrediction = async (event) => {
    event?.preventDefault();

    const cveId = liveCveId.trim().toUpperCase();

    if (!/^CVE-\d{4}-\d{4,}$/.test(cveId)) {
      setLivePrediction(null);
      setLivePredictionError(
        "Enter a valid CVE ID, for example CVE-2021-44228."
      );
      return;
    }

    setLiveCveId(cveId);
    setLivePredictionLoading(true);
    setLivePredictionError("");
    setLivePrediction(null);

    try {
      const response = await fetch(
        `${API_BASE}/api/predict-live/${encodeURIComponent(cveId)}`,
        {
          method: "GET",
          headers: { Accept: "application/json" },
        }
      );

      const data = await response.json().catch(() => null);

      if (!response.ok) {
        throw new Error(
          data?.detail ||
            data?.message ||
            `Prediction failed (${response.status}). Check that the backend GET endpoint is available.`
        );
      }

      setLivePrediction(data);
    } catch (error) {
      setLivePredictionError(
        error.message ||
          "Could not connect to the prediction API. Check that the backend is running."
      );
    } finally {
      setLivePredictionLoading(false);
    }
  };

  const navigateTo = (tab) => {
    setActiveTab(tab);
    setSeverityFilter("ALL");
    setSearch("");
  };

  const modelStatement = hideKev
    ? "Highest predicted likelihood of joining CISA KEV, among CVEs not yet listed."
    : "Highest predicted likelihood of CISA KEV inclusion, including CVEs already listed.";

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
          <span className={`environment-pill ${apiStatus}`}>
            <span className="live-dot" />
            {apiStatus === "online"
              ? "API CONNECTED"
              : apiStatus === "offline"
                ? "API OFFLINE"
                : "CONNECTING"}
          </span>

          <ThemeToggle theme={theme} onToggle={toggleTheme} />

          <div className="avatar">VI</div>
        </div>
      </header>

      <main className="main-content">
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
                  ? "Model-ranked CVE list"
                  : "AI explainability"}
            </h1>

            <p className="page-description">
              {activeTab === "Overview"
                ? "Dataset exposure, what the model learned, and the CVEs it flags first."
                : activeTab === "Vulnerabilities"
                  ? "Search for a CVE to predict its KEV inclusion likelihood, or browse the model-ranked list below."
                  : selectedCve
                    ? `SHAP feature contributions for ${selectedCve.id}.`
                    : "Select a CVE from the Vulnerabilities page to inspect its SHAP explanation."}
            </p>
          </div>
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
                tone="violet"
                note="Dataset"
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
                    <h3>What the model weighs most</h3>
                    <p>
                      {modelInfo?.model_name
                        ? `${modelInfo.model_name} · predicts CISA KEV inclusion`
                        : "Global feature importance"}
                    </p>
                  </div>

                  <span className="panel-icon">
                    <BrainCircuit size={18} />
                  </span>
                </div>

                {modelInfoError ? (
                  <div className="empty-state">
                    <strong>Model details unavailable</strong>
                    <p>{modelInfoError}</p>
                  </div>
                ) : !modelInfo ? (
                  <p className="chart-footnote">Loading model details...</p>
                ) : (
                  <>
                    {metricChips.length > 0 && (
                      <div className="metric-row">
                        {metricChips.map((chip) => (
                          <span key={chip.label} className="metric-chip">
                            <span>{chip.label}</span>
                            <strong>{chip.value}</strong>
                          </span>
                        ))}
                      </div>
                    )}

                    {importanceData.length > 0 ? (
                      <div className="trend-chart">
                        <ResponsiveContainer width="100%" height="100%">
                          <BarChart
                            data={importanceData}
                            layout="vertical"
                            margin={{ top: 5, right: 16, left: 4, bottom: 0 }}
                          >
                            <CartesianGrid
                              stroke={colors.grid}
                              strokeDasharray="3 3"
                              horizontal={false}
                            />

                            <XAxis
                              type="number"
                              axisLine={false}
                              tickLine={false}
                              tick={{ fill: colors.tick, fontSize: 11 }}
                            />

                            <YAxis
                              type="category"
                              dataKey="feature"
                              width={140}
                              axisLine={false}
                              tickLine={false}
                              tick={{ fill: colors.tickStrong, fontSize: 10 }}
                            />

                            <Tooltip
                              cursor={{ fill: colors.bar, fillOpacity: 0.08 }}
                              contentStyle={tooltipStyle}
                              itemStyle={{ color: colors.tooltipText }}
                              labelStyle={{ color: colors.tooltipText }}
                              formatter={(value) => [
                                Number(value).toFixed(4),
                                "Mean |SHAP|",
                              ]}
                            />

                            <Bar
                              dataKey="importance"
                              fill={colors.bar}
                              radius={[0, 4, 4, 0]}
                              maxBarSize={18}
                            />
                          </BarChart>
                        </ResponsiveContainer>
                      </div>
                    ) : (
                      <p className="chart-footnote">
                        The backend did not return feature importance.
                      </p>
                    )}

                    <p className="chart-footnote">
                      Metrics are from the held-out test set
                      {modelInfo.positive_rate != null
                        ? `, where only ${formatPercent(
                            modelInfo.positive_rate
                          )} of CVEs are in KEV. With classes this uneven, PR-AUC and recall say more than accuracy.`
                        : "."}
                    </p>
                  </>
                )}
              </article>
            </section>

            <section className="panel table-panel">
              <div className="panel-heading table-panel-heading">
                <div>
                  <h3>Top model-ranked CVEs</h3>
                  <p>{modelStatement}</p>
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
          <>
            {/* 1. Live CVE Prediction at the top */}

            <section className="panel explorer-panel">
              <div className="panel-heading">
                <div>
                  <h3>Live CVE Prediction</h3>
                  <p>
                    Enter a CVE ID to retrieve its vulnerability details and
                    estimate its likelihood of CISA KEV inclusion.
                  </p>
                </div>

                <span className="panel-icon">
                  <Sparkles size={18} />
                </span>
              </div>

              <form
                onSubmit={runLivePrediction}
                className="live-prediction-form"
              >
                <label
                  htmlFor="live-cve-id"
                  className="live-prediction-label"
                >
                  CVE ID
                </label>

                <div className="live-prediction-controls">
                  <input
                    id="live-cve-id"
                    className="live-cve-input"
                    type="text"
                    value={liveCveId}
                    onChange={(event) => setLiveCveId(event.target.value)}
                    placeholder="e.g. CVE-2021-44228"
                    autoComplete="off"
                    spellCheck={false}
                    aria-describedby="live-cve-help"
                  />

                  <button
                    className="primary-button live-predict-button"
                    type="submit"
                    disabled={livePredictionLoading}
                  >
                    <BrainCircuit size={16} />
                    {livePredictionLoading
                      ? "Fetching and predicting..."
                      : "Predict CVE"}
                  </button>
                </div>

                <p id="live-cve-help" className="live-cve-help">
                  Example: CVE-2021-44228 (Log4Shell). The backend retrieves
                  available data from NVD and FIRST EPSS before running the
                  trained model.
                </p>
              </form>

              {livePredictionError && (
                <div className="empty-state" role="alert">
                  <strong>Prediction failed</strong>
                  <p>{livePredictionError}</p>
                </div>
              )}

              {livePrediction && (
                <div className="live-prediction-result">
                  <div className="panel-heading">
                    <div>
                      <h3>{livePrediction.cve_id || liveCveId}</h3>
                      <p>
                        {livePrediction.source || "Live CVE lookup"}
                      </p>
                    </div>

                    <span className="panel-icon">
                      <ShieldCheck size={18} />
                    </span>
                  </div>

                  <p className="live-prediction-description">
                    {livePrediction.description || "No description available."}
                  </p>

                  <div className="stats-grid live-prediction-metrics">
                    <StatCard
                      icon={Target}
                      label="Model KEV probability"
                      value={formatProbability(
                        toNumberOrNull(livePrediction.kev_probability)
                      )}
                      tone="violet"
                      note="Model estimate"
                    />

                    <StatCard
                      icon={ShieldAlert}
                      label="Predicted KEV inclusion"
                      value={
                        livePrediction.predicted_kev == null
                          ? "N/A"
                          : livePrediction.predicted_kev
                            ? "Likely"
                            : "Unlikely"
                      }
                      tone="red"
                      note="Prediction"
                    />

                    <StatCard
                      icon={Gauge}
                      label="CVSS score"
                      value={
                        livePrediction.cvss_score == null
                          ? "N/A"
                          : Number(livePrediction.cvss_score).toFixed(1)
                      }
                      tone="amber"
                      note={livePrediction.cvss_severity || "Severity"}
                    />

                    <StatCard
                      icon={ShieldCheck}
                      label="EPSS score"
                      value={
                        livePrediction.epss_score == null
                          ? "N/A"
                          : formatPercent(livePrediction.epss_score)
                      }
                      tone="green"
                      note="Exploit prediction"
                    />
                  </div>

                  {livePrediction.published_date && (
                    <div className="modal-info-row live-prediction-metadata">
                      <span>Published date</span>
                      <strong>{livePrediction.published_date}</strong>
                    </div>
                  )}

                  {livePrediction.epss_percentile != null && (
                    <div className="modal-info-row live-prediction-metadata">
                      <span>EPSS percentile</span>
                      <strong>
                        {formatPercent(livePrediction.epss_percentile)}
                      </strong>
                    </div>
                  )}

                  <p
                    className="chart-footnote"
                    style={{ marginTop: "16px" }}
                  >
                    Source: {livePrediction.source || "NVD + FIRST EPSS"}.{" "}
                    {livePrediction.interpretation ||
                      "The probability is a model estimate, not a guarantee of exploitation."}
                  </p>

                  <button
                    className="primary-button modal-action"
                    type="button"
                    onClick={() => {
                      setSelectedCve({
                        id: livePrediction.cve_id || liveCveId,
                        title:
                          livePrediction.description ||
                          "Live CVE prediction",
                        description:
                          livePrediction.description ||
                          "No description available.",
                        score:
                          livePrediction.cvss_score ??
                          livePrediction.base_score ??
                          null,
                        severity:
                          livePrediction.cvss_severity ||
                          livePrediction.base_severity ||
                          "UNKNOWN",
                        epss: livePrediction.epss_score ?? null,
                        date: livePrediction.published_date || "Unknown",
                        modelScore: livePrediction.kev_probability ?? null,
                      });

                      setShowDetails(false);
                      setShapExplanation(null);
                      setShapError("");
                      setActiveTab("Explainability");
                    }}
                  >
                    <BrainCircuit size={16} />
                    Explain this prediction
                  </button>
                </div>
              )}
            </section>

            {/* 2. Model-ranked vulnerability list below */}

            <section className="panel table-panel">
              <div className="panel-heading table-panel-heading">
                <div>
                  <h3>Model-ranked CVE list</h3>
                  <p>
                    CVEs ordered by the trained model's probability of CISA
                    KEV inclusion.
                  </p>
                </div>
              </div>

              {apiError ? (
                <div className="empty-state">
                  <strong>Unable to load vulnerability records</strong>
                  <p>{apiError}</p>
                </div>
              ) : loading ? (
                <p className="chart-footnote">Loading CVE records...</p>
              ) : vulnerabilities.length === 0 ? (
                <div className="empty-state">
                  <strong>No vulnerability records found</strong>
                  <p>
                    The backend returned no CVEs matching the current filters.
                  </p>
                </div>
              ) : (
                <>
                  <VulnerabilityTable
                    rows={vulnerabilities}
                    onSelect={openCve}
                  />

                  <p className="chart-footnote">
                    Showing {vulnerabilities.length} of{" "}
                    {formatNumber(totalMatches)} matching records. Select a
                    row to view its model prediction and details.
                  </p>
                </>
              )}
            </section>
          </>
        )}

        {/* ---------- SHAP explainability ---------- */}

        {activeTab === "Explainability" && (
          <section className="explain-grid">
            <article className="panel explain-main">
              <div className="panel-heading">
                <div>
                  <h3>SHAP feature contributions</h3>
                  <p>
                    {selectedCve
                      ? `Explanation for ${selectedCve.id}`
                      : "Select a CVE to begin"}
                  </p>
                </div>

                <span className="panel-icon">
                  <BrainCircuit size={18} />
                </span>
              </div>

              {!selectedCve ? (
                <div className="empty-state">
                  <BrainCircuit size={30} />
                  <strong>No CVE selected</strong>
                  <p>
                    Open the Vulnerabilities page, select a CVE, and click
                    "View SHAP explanation" to see its feature contributions.
                  </p>

                  <button
                    className="primary-button"
                    onClick={() => navigateTo("Vulnerabilities")}
                  >
                    <FileSearch size={16} />
                    Choose a CVE
                  </button>
                </div>
              ) : shapLoading ? (
                <div className="empty-state">
                  <BrainCircuit size={28} />
                  <strong>Calculating explanation...</strong>
                  <p>
                    Fetching SHAP contributions for {selectedCve.id} from the
                    backend.
                  </p>
                </div>
              ) : shapError ? (
                <div className="empty-state">
                  <AlertTriangle size={28} />
                  <strong>Could not load SHAP explanation</strong>
                  <p role="alert">{shapError}</p>

                  <button
                    className="secondary-button"
                    onClick={() => setShapRetry((value) => value + 1)}
                  >
                    Try again
                  </button>
                </div>
              ) : shapExplanation ? (
                <>
                  <div className="explain-callout">
                    <Sparkles size={19} />

                    <div>
                      <strong>Why the model scored this CVE as it did</strong>
                      <p>
                        Each bar is how much a feature moved this CVE's score
                        away from the model's baseline. Positive values raise
                        the predicted KEV likelihood; negative values lower
                        it.
                      </p>
                    </div>
                  </div>

                  <div className="feature-chart">
                    <ResponsiveContainer width="100%" height="100%">
                      <BarChart
                        data={shapExplanation.contributions}
                        layout="vertical"
                        margin={{ top: 5, right: 25, left: 8, bottom: 5 }}
                      >
                        <CartesianGrid
                          stroke={colors.grid}
                          strokeDasharray="3 3"
                          horizontal={false}
                        />

                        <XAxis
                          type="number"
                          domain={["auto", "auto"]}
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
                          tick={{ fill: colors.tickStrong, fontSize: 10 }}
                        />

                        <Tooltip
                          contentStyle={tooltipStyle}
                          itemStyle={{ color: colors.tooltipText }}
                          labelStyle={{ color: colors.tooltipText }}
                          formatter={(value) => [
                            Number(value).toFixed(6),
                            "SHAP value",
                          ]}
                        />

                        <Bar
                          dataKey="impact"
                          name="SHAP contribution"
                          radius={[0, 4, 4, 0]}
                        >
                          {shapExplanation.contributions.map((item) => (
                            <Cell
                              key={item.feature}
                              fill={
                                item.impact >= 0
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
                      <i className="positive-dot" />
                      Raises predicted likelihood
                    </span>

                    <span>
                      <i className="negative-dot" />
                      Lowers predicted likelihood
                    </span>
                  </div>

                  <div className="modal-info-row">
                    <span>Selected CVE</span>
                    <strong>
                      {shapExplanation.cve_id || selectedCve.id}
                    </strong>
                  </div>

                  {shapExplanation.base_value != null && (
                    <div className="modal-info-row">
                      <span>Model base value</span>
                      <strong>
                        {Number(shapExplanation.base_value).toFixed(6)}
                      </strong>
                    </div>
                  )}

                  <p className="chart-footnote">
                    Method:{" "}
                    {shapExplanation.explanation_type ||
                      "SHAP feature contributions"}
                    . SHAP shows what drove the model's output. It does not
                    show that a vulnerability is safe or exploitable.
                  </p>
                </>
              ) : (
                <div className="empty-state">
                  <strong>No explanation available</strong>
                  <p>
                    The backend did not return an explanation for this CVE.
                  </p>

                  <button
                    className="secondary-button"
                    onClick={() => setShapRetry((value) => value + 1)}
                  >
                    Try again
                  </button>
                </div>
              )}
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
                  <strong>Feature contribution</strong>
                  <p>
                    Each bar shows the SHAP value calculated for one feature
                    in the selected CVE's explanation.
                  </p>
                </div>
              </div>

              <div className="guide-item">
                <span className="guide-number">02</span>
                <div>
                  <strong>Positive contribution</strong>
                  <p>
                    A positive value pushes the model output higher than its
                    baseline.
                  </p>
                </div>
              </div>

              <div className="guide-item">
                <span className="guide-number">03</span>
                <div>
                  <strong>Negative contribution</strong>
                  <p>
                    A negative value pushes the model output lower than its
                    baseline.
                  </p>
                </div>
              </div>

              <div className="method-note">
                <BrainCircuit size={18} />
                <div>
                  <strong>Method: SHAP</strong>
                  <p>
                    SHAP assigns each input feature a share of the model's
                    output. Interpret values in the context of the model and
                    target class.
                  </p>
                </div>
              </div>

              {selectedCve && (
                <button
                  className="secondary-button"
                  onClick={() => setShapRetry((value) => value + 1)}
                  disabled={shapLoading}
                >
                  Refresh explanation
                </button>
              )}
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
              CVE RECORD · MODEL RANK #{selectedCve.rank}
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
                <span>Model KEV probability</span>
                <strong>
                  {formatProbability(
                    modelPrediction?.kev_probability ?? selectedCve.modelScore
                  )}
                </strong>
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
                AI model prediction
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
                      {formatProbability(modelPrediction.kev_probability)}
                    </strong>
                  </div>

                  {modelPrediction.interpretation && (
                    <p className="chart-footnote">
                      {modelPrediction.interpretation}
                    </p>
                  )}
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
                <strong>{selectedCve.vector || "N/A"}</strong>
              </div>

              <div className="modal-info-row">
                <span>Published date</span>
                <strong>{selectedCve.date}</strong>
              </div>

              <div className="modal-info-row">
                <span>CISA KEV status in dataset</span>
                <strong>{selectedCve.status || "Live prediction"}</strong>
              </div>
            </div>

            <div className="modal-disclaimer">
              <AlertTriangle size={16} />
              The model estimates CISA KEV inclusion; it is not a CVSS score
              or a guarantee of exploitation. Verify findings against
              authoritative vulnerability sources.
            </div>

            <button
              className="primary-button modal-action"
              onClick={() => {
                setShowDetails(false);
                setShapExplanation(null);
                setShapError("");
                setActiveTab("Explainability");
              }}
            >
              <BrainCircuit size={16} />
              View SHAP explanation
            </button>
          </section>
        </div>
      )}
    </div>
  );
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
            <th>MODEL KEV RISK</th>
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
                <ModelRiskCell value={cve.modelScore} />
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