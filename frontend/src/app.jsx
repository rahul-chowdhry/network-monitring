import { useEffect, useState } from "react";
import {
  getDevices,
  getToken,
  login,
  logout,
} from "./api";


function LoginScreen({ onLogin }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function handleSubmit(event) {
    event.preventDefault();

    setError("");
    setLoading(true);

    try {
      const result = await login(username, password);
      onLogin({
        username: username,
      });
    } catch (err) {
      setError(err.message || "Login failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="login-page">
      <div className="login-card">
        <div className="login-brand">
          <div className="login-icon">⌁</div>

          <p className="eyebrow">LOCAL NETWORK SECURITY</p>

          <h1>HOMENET SENTINEL</h1>

          <p>
            Sign in to access your home-network monitoring dashboard.
          </p>
        </div>

        <form onSubmit={handleSubmit} className="login-form">
          <label>
            Username
            <input
              type="text"
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              placeholder="Enter username"
              autoComplete="username"
              required
            />
          </label>

          <label>
            Password
            <input
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              placeholder="Enter password"
              autoComplete="current-password"
              required
            />
          </label>

          {error && (
            <div className="error-message">
              {error}
            </div>
          )}

          <button
            type="submit"
            className="login-button"
            disabled={loading}
          >
            {loading ? "Signing in..." : "Sign In"}
          </button>
        </form>

        <div className="login-footer">
          Local access only
        </div>
      </div>
    </div>
  );
}


function Dashboard({ user, onLogout }) {
  const [devices, setDevices] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  async function loadDevices() {
    try {
      setError("");

      const data = await getDevices();

      setDevices(data.devices || []);
    } catch (err) {
      setError(err.message || "Failed to load devices");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadDevices();
  }, []);

  const onlineDevices = devices.filter(
    (device) => device.status === "online"
  );

  const offlineDevices = devices.filter(
    (device) => device.status === "offline"
  );

  const openPorts = devices.reduce(
    (total, device) =>
      total +
      (device.ports?.filter(
        (port) => port.state === "open"
      ).length || 0),
    0
  );

  return (
    <div className="app">
      <header className="topbar">
        <div>
          <h1>HOMENET SENTINEL</h1>
          <p>Home Network Monitoring Dashboard</p>
        </div>

        <div className="topbar-right">
          <div className="connection-status">
            <span className="status-dot"></span>
            Backend Online
          </div>

          <div className="user-area">
            <span>{user?.username}</span>

            <button
              type="button"
              className="logout-button"
              onClick={() => {
                logout();
                onLogout();
              }}
            >
              Logout
            </button>
          </div>
        </div>
      </header>

      <main className="dashboard">
        <section className="welcome-card">
          <div>
            <p className="eyebrow">NETWORK SECURITY</p>

            <h2>Home Network Overview</h2>

            <p className="description">
              Real-time inventory from your local network scanner
              and HOMENET SENTINEL database.
            </p>
          </div>

          <div className="network-icon">⌁</div>
        </section>

        <section className="stats-grid">
          <div className="stat-card">
            <span className="stat-label">
              TOTAL DEVICES
            </span>

            <strong>{devices.length}</strong>

            <small>
              Actual database records
            </small>
          </div>

          <div className="stat-card">
            <span className="stat-label">
              ONLINE
            </span>

            <strong>{onlineDevices.length}</strong>

            <small>
              Currently discovered online
            </small>
          </div>

          <div className="stat-card">
            <span className="stat-label">
              OFFLINE
            </span>

            <strong>{offlineDevices.length}</strong>

            <small>
              Known offline devices
            </small>
          </div>

          <div className="stat-card">
            <span className="stat-label">
              OPEN PORTS
            </span>

            <strong>{openPorts}</strong>

            <small>
              Open TCP/UDP services
            </small>
          </div>
        </section>

        <section className="devices-section">
          <div className="section-header">
            <div>
              <p className="eyebrow">
                NETWORK INVENTORY
              </p>

              <h2>Discovered Devices</h2>

              <p className="section-description">
                Real devices returned by the authenticated
                HOMENET SENTINEL API.
              </p>
            </div>

            <button
              type="button"
              className="scan-button"
              onClick={loadDevices}
              disabled={loading}
            >
              {loading ? "Loading..." : "Refresh Devices"}
            </button>
          </div>

          {error && (
            <div className="error-message dashboard-error">
              {error}
            </div>
          )}

          {loading ? (
            <div className="empty-state">
              <div className="loading-spinner"></div>

              <h3>Loading network devices</h3>

              <p>
                Reading real device information from the
                HOMENET SENTINEL API.
              </p>
            </div>
          ) : devices.length === 0 ? (
            <div className="empty-state">
              <div className="empty-icon">⌁</div>

              <h3>No devices found</h3>

              <p>
                The API returned zero devices from the
                database.
              </p>
            </div>
          ) : (
            <div className="device-table-wrapper">
              <table className="device-table">
                <thead>
                  <tr>
                    <th>Status</th>
                    <th>IP Address</th>
                    <th>Hostname</th>
                    <th>MAC Address</th>
                    <th>Vendor</th>
                    <th>Latency</th>
                    <th>Open Ports</th>
                  </tr>
                </thead>

                <tbody>
                  {devices.map((device) => {
                    const deviceOpenPorts =
                      device.ports?.filter(
                        (port) =>
                          port.state === "open"
                      ).length || 0;

                    const currentIp =
                      device.ips?.find(
                        (ip) => ip.is_current
                      )?.ip_address ||
                      device.ips?.[0]?.ip_address ||
                      "Unknown";

                    return (
                      <tr key={device.id}>
                        <td>
                          <span
                            className={`device-status ${
                              device.status
                            }`}
                          >
                            <span></span>

                            {device.status}
                          </span>
                        </td>

                        <td className="mono">
                          {currentIp}
                        </td>

                        <td>
                          {device.hostname || "Unknown"}
                        </td>

                        <td className="mono">
                          {device.mac_address || "Unavailable"}
                        </td>

                        <td>
                          {device.vendor || "Unknown"}
                        </td>

                        <td>
                          {device.latency_ms !== null &&
                          device.latency_ms !== undefined
                            ? `${Number(
                                device.latency_ms
                              ).toFixed(2)} ms`
                            : "—"}
                        </td>

                        <td>
                          <span className="port-count">
                            {deviceOpenPorts}
                          </span>
                          {deviceOpenPorts === 1
                            ? " open"
                            : " open"}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </main>
    </div>
  );
}


function App() {
  const [user, setUser] = useState(null);
  const [checkingSession, setCheckingSession] =
    useState(true);

  useEffect(() => {
    const token = getToken();

    if (token) {
      setUser({
        username: "admin",
      });
    }

    setCheckingSession(false);
  }, []);

  if (checkingSession) {
    return (
      <div className="loading-page">
        Loading HOMENET SENTINEL...
      </div>
    );
  }

  if (!user) {
    return (
      <LoginScreen
        onLogin={(loggedInUser) => {
          setUser(loggedInUser);
        }}
      />
    );
  }

  return (
    <Dashboard
      user={user}
      onLogout={() => setUser(null)}
    />
  );
}


export default App;