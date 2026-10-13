import { useState } from "react";
import "./App.css";

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000").replace(/\\/$/, "");

function App() {
  const [repoUrl, setRepoUrl] = useState("");
  const [scanStatus, setScanStatus] = useState("waiting");
  const [scanResult, setScanResult] = useState(null);
  const [error, setError] = useState("");

  const startDeployment = async () => {
    if (!repoUrl.trim()) {
      setError("Please enter a GitHub repository URL.");
      return;
    }

    setError("");
    setScanResult(null);
    setScanStatus("running");

    try {
      const response = await fetch(`${API_BASE_URL}/scan`, {
        method: "POST",

        headers: {
          "Content-Type": "application/json",
        },

        body: JSON.stringify({
          repo_url: repoUrl.trim(),
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.detail || data.message || "Security scan failed."
        );
      }

      setScanResult(data);

      if (
        data.security_status === "PASSED" ||
        data.status === "PASSED" ||
        data.status === "SUCCESS"
      ) {
        setScanStatus("passed");
      } else {
        setScanStatus("failed");
      }
    } catch (err) {
      console.error(err);

      setError(err.message || "Unable to connect to CloudGuard backend.");
      setScanStatus("failed");
    }
  };

  return (
    <div className="app">

      {/* NAVBAR */}

      <header className="navbar">
        <div className="brand">
          <div className="shield">CG</div>

          <div>
            <h2>CloudGuard</h2>
            <span>Secure Deployment Platform</span>
          </div>
        </div>

        <div className="status">
          <span className="status-dot"></span>
          System Ready
        </div>
      </header>


      <main className="container">

        {/* HERO */}

        <section className="hero">

          <p className="tag">
            SECURE • BUILD • DEPLOY
          </p>

          <h1>
            Deploy your code
            <span> securely.</span>
          </h1>

          <p className="description">
            Enter a GitHub repository and CloudGuard will scan,
            build and deploy your application automatically.
          </p>

        </section>


        {/* REPOSITORY INPUT */}

        <section className="deploy-card">

          <label>GitHub Repository</label>

          <div className="repo-input">

            <span>⌘</span>

            <input
              type="text"
              placeholder="https://github.com/username/repository"
              value={repoUrl}
              onChange={(e) => setRepoUrl(e.target.value)}
              disabled={scanStatus === "running"}
            />

            <button
              onClick={startDeployment}
              disabled={scanStatus === "running"}
            >

              {scanStatus === "running"
                ? "Scanning..."
                : "Start Deployment →"}

            </button>

          </div>


          {error && (
            <div className="error-message">
              {error}
            </div>
          )}

        </section>


        {/* PIPELINE */}

        <section className="pipeline">

          <div className="section-heading">

            <div>
              <p>PIPELINE</p>
              <h2>Deployment Progress</h2>
            </div>

            <span>
              {scanStatus === "waiting" && "Waiting for repository"}

              {scanStatus === "running" && "CloudGuard is scanning..."}

              {scanStatus === "passed" && "Security scan passed"}

              {scanStatus === "failed" && "Security scan failed"}
            </span>

          </div>


          <div className="steps">

            <PipelineStep
              number="01"
              title="Clone Repository"
              description="Fetch source code from GitHub"
              status={
                scanStatus === "waiting"
                  ? "waiting"
                  : scanStatus === "running"
                  ? "running"
                  : scanStatus === "passed"
                  ? "passed"
                  : "failed"
              }
            />


            <PipelineStep
              number="02"
              title="Security Scan"
              description="Scan code, secrets and dependencies"
              status={scanStatus}
            />


            <PipelineStep
              number="03"
              title="Docker Build"
              description="Build secure Docker image"
              status="waiting"
            />


            <PipelineStep
              number="04"
              title="Deploy"
              description="Launch application container"
              status="waiting"
            />

          </div>

        </section>


        {/* SECURITY RESULT */}

        {scanResult && (

          <section className="pipeline">

            <div className="section-heading">

              <div>
                <p>SECURITY</p>
                <h2>Scan Results</h2>
              </div>

              <span>
                {scanResult.security_status || scanResult.status}
              </span>

            </div>


            <pre
              style={{
                whiteSpace: "pre-wrap",
                color: "#94a3b8",
                fontSize: "12px",
                lineHeight: "1.6",
                overflowX: "auto",
              }}
            >
              {JSON.stringify(scanResult, null, 2)}
            </pre>

          </section>

        )}

      </main>

    </div>
  );
}


function PipelineStep({
  number,
  title,
  description,
  status,
}) {

  const statusText = {
    waiting: "Waiting",
    running: "Running...",
    passed: "Passed ✓",
    failed: "Failed ✕",
  };

  return (

    <div className="pipeline-step">

      <div className="step-number">
        {number}
      </div>


      <div>

        <h3>{title}</h3>

        <p>
          {description}
        </p>

      </div>


      <div
        className="waiting"
        style={{
          color:
            status === "passed"
              ? "#22c55e"
              : status === "failed"
              ? "#ef4444"
              : status === "running"
              ? "#38bdf8"
              : "#64748b",
        }}
      >

        {statusText[status]}

      </div>

    </div>

  );
}


export default App;