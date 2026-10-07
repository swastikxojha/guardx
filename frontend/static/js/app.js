let TOKEN = localStorage.getItem("gx_token") || "";
const app = document.getElementById("app");
const title = document.getElementById("page-title");
document.getElementById("token").value = TOKEN;

function esc(value) {
  const entities = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
  return String(value ?? "").replace(/[&<>"']/g, (character) => entities[character]);
}

function saveToken() {
  TOKEN = document.getElementById("token").value.trim();
  localStorage.setItem("gx_token", TOKEN);
  load("dashboard");
}

async function api(path, opt = {}) {
  opt.headers = {
    ...(opt.headers || {}),
    "Content-Type": "application/json",
    ...(TOKEN ? { Authorization: "Bearer " + TOKEN } : {}),
  };
  const response = await fetch("/api/v1" + path, opt);
  if (!response.ok) throw new Error(await response.text());
  return response.json();
}

async function load(page) {
  title.textContent = page[0].toUpperCase() + page.slice(1);
  document.querySelectorAll("nav button").forEach((button) => {
    button.classList.toggle("active", button.dataset.page === page);
  });

  if (page === "dashboard") {
    const data = await api("/analytics");
    const cards = [
      ["Requests", data.total_requests],
      ["Allowed", data.decision_distribution.ALLOW],
      ["Blocked", data.decision_distribution.BLOCK],
      ["Avg risk", data.average_risk],
    ];
    app.innerHTML =
      '<div class="grid">' +
      cards.map((item) => '<div class="card"><div class="muted">' + esc(item[0]) +
        '</div><div class="metric">' + esc(item[1]) + "</div></div>").join("") +
      '</div><div class="two panel"><div class="card"><h3>Decision distribution</h3><pre class="result">' +
      esc(JSON.stringify(data.decision_distribution, null, 2)) +
      '</pre></div><div class="card"><h3>Threat categories</h3><pre class="result">' +
      esc(JSON.stringify(data.threat_categories, null, 2)) + "</pre></div></div>";
  } else if (page === "applications") {
    const items = await api("/applications");
    app.innerHTML =
      '<div class="card form"><h3>Applications</h3><input class="field" id="aname" placeholder="Application name">' +
      '<input class="field" id="adesc" placeholder="Description"><button class="btn" onclick="createApp()">Add application</button>' +
      '<div class="result">' +
      (items.map((item) => esc(item.name) + " — " + esc(item.description || "")).join("\n") || "No applications yet.") +
      "</div></div>";
  } else if (page === "keys") {
    const items = await api("/api-keys");
    app.innerHTML =
      '<div class="card form"><h3>API Keys</h3><input class="field" id="kname" placeholder="Key name">' +
      '<button class="btn" onclick="createKey()">Create key</button><div class="result">' +
      (items.map((item) => esc(item.name) + " — " + (item.revoked ? "revoked" : "active")).join("\n") || "No API keys yet.") +
      "</div></div>";
  } else if (page === "check") {
    app.innerHTML =
      '<div class="card form"><label>Evaluation type<select id="ctype"><option value="input">Input</option>' +
      '<option value="output">Output</option></select></label><textarea id="content" rows="9" ' +
      'placeholder="Enter a prompt, response, or sensitive action description..."></textarea>' +
      '<button class="btn" onclick="runCheck()">Evaluate with GuardX</button><div id="result"></div></div>';
  } else if (page === "requests") {
    const rows = await api("/audit/requests");
    app.innerHTML =
      '<div class="card"><table class="table"><tr><th>Time</th><th>Type</th><th>Risk</th>' +
      "<th>Decision</th><th>Categories</th></tr>" +
      rows.map((item) =>
        "<tr><td>" + esc(new Date(item.created_at).toLocaleString()) +
        "</td><td>" + esc(item.request_type) +
        '</td><td>' + esc(Number(item.risk_score).toFixed(2)) +
        ' <span class="risk ' + esc(item.risk_level) + '">' + esc(item.risk_level) +
        '</span></td><td class="' + esc(item.decision) + '">' + esc(item.decision) +
        "</td><td>" + esc((item.categories || []).join(", ")) + "</td></tr>"
      ).join("") + "</table></div>";
  } else if (page === "policies") {
    app.innerHTML =
      '<div class="card form"><h3>Create policy</h3><input class="field" id="pname" placeholder="Policy name">' +
      '<input class="field" id="pcat" placeholder="Category e.g. credentials"><select id="pact">' +
      "<option>BLOCK</option><option>MODIFY</option><option>HUMAN_REVIEW</option></select>" +
      '<button class="btn" onclick="createPolicy()">Save policy</button><div id="plist"></div></div>';
    const policies = await api("/policies");
    document.getElementById("plist").innerHTML = policies.map((policy) =>
      '<div class="result"><b>' + esc(policy.name) + "</b> · " +
      (policy.enabled ? "enabled" : "disabled") + "</div>"
    ).join("");
  } else if (page === "reviews") {
    const reviews = await api("/reviews");
    app.innerHTML =
      '<div class="card"><table class="table"><tr><th>Status</th><th>Decision</th>' +
      "<th>Comment</th></tr>" +
      reviews.map((review) =>
        "<tr><td>" + esc(review.status) + "</td><td>" +
        esc(review.decision || "PENDING") + "</td><td>" + esc(review.comment || "") + "</td></tr>"
      ).join("") + "</table></div>";
  } else {
    app.innerHTML =
      '<div class="card"><h3>GuardX settings</h3><p class="muted">Use the REST API or SDK for application integration. ' +
      "Configure thresholds and providers through environment variables.</p><pre class=\"result\">" +
      "GET /docs\nPOST /api/v1/check/input\nPOST /api/v1/check/output\nPOST /api/v1/check/action</pre></div>";
  }
}

async function createApp() {
  try {
    await api("/applications", {
      method: "POST",
      body: JSON.stringify({
        name: document.getElementById("aname").value,
        description: document.getElementById("adesc").value,
      }),
    });
    load("applications");
  } catch (error) {
    alert(error.message);
  }
}

async function createKey() {
  try {
    const result = await api("/api-keys", {
      method: "POST",
      body: JSON.stringify({ name: document.getElementById("kname").value, scopes: ["guard:check"] }),
    });
    alert("Copy this key now; it is shown only once:\n\n" + result.api_key);
    load("keys");
  } catch (error) {
    alert(error.message);
  }
}

async function runCheck() {
  const content = document.getElementById("content").value;
  const type = document.getElementById("ctype").value;
  try {
    const result = await api("/check/" + type, {
      method: "POST",
      body: JSON.stringify({ content }),
    });
    const container = document.createElement("div");
    container.className = "result";
    const decision = document.createElement("b");
    decision.className = result.decision;
    decision.textContent = result.decision;
    const summary = document.createElement("div");
    summary.append(decision, document.createTextNode(
      " · risk " + result.risk_score + " (" + result.risk_level + ")"
    ));
    const details = document.createElement("pre");
    details.textContent = JSON.stringify(result, null, 2);
    container.append(summary, details);
    document.getElementById("result").replaceChildren(container);
  } catch (error) {
    document.getElementById("result").textContent = error.message;
  }
}

async function createPolicy() {
  try {
    await api("/policies", {
      method: "POST",
      body: JSON.stringify({
        name: document.getElementById("pname").value,
        rules: [{
          category: document.getElementById("pcat").value,
          action: document.getElementById("pact").value,
        }],
      }),
    });
    load("policies");
  } catch (error) {
    alert(error.message);
  }
}

document.querySelectorAll("nav button").forEach((button) => {
  button.onclick = () => load(button.dataset.page);
});

load("dashboard").catch(() => {
  app.innerHTML =
    '<div class="card form"><h3>Connect to GuardX</h3><input class="field" id="lemail" placeholder="Email">' +
    '<input class="field" id="lpass" placeholder="Password" type="password">' +
    '<button class="btn" onclick="login()">Login</button><hr><input class="field" id="sorg" placeholder="Organization">' +
    '<button class="btn" onclick="signup()">Create account</button><p class="muted">Password must be at least 8 characters.</p></div>';
});

async function login() {
  try {
    const response = await fetch("/api/v1/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email: document.getElementById("lemail").value,
        password: document.getElementById("lpass").value,
      }),
    });
    if (!response.ok) throw new Error(await response.text());
    TOKEN = (await response.json()).access_token;
    localStorage.setItem("gx_token", TOKEN);
    document.getElementById("token").value = TOKEN;
    load("dashboard");
  } catch (error) {
    alert(error.message);
  }
}

async function signup() {
  try {
    const response = await fetch("/api/v1/auth/signup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email: document.getElementById("lemail").value,
        password: document.getElementById("lpass").value,
        organization_name: document.getElementById("sorg").value,
      }),
    });
    if (!response.ok) throw new Error(await response.text());
    TOKEN = (await response.json()).access_token;
    localStorage.setItem("gx_token", TOKEN);
    document.getElementById("token").value = TOKEN;
    load("dashboard");
  } catch (error) {
    alert(error.message);
  }
}
