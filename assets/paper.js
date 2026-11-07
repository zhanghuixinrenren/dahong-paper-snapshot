const state = {
  payload: null,
  accountKey: "optimized",
  activityMode: "trades",
  positionQuery: "",
};

const elements = {
  asOf: document.getElementById("as-of"),
  generatedAt: document.getElementById("generated-at"),
  statusTitle: document.getElementById("status-title"),
  overview: document.getElementById("overview-grid"),
  tabs: document.getElementById("account-tabs"),
  view: document.getElementById("account-view"),
  errorPanel: document.getElementById("error-panel"),
  errorCopy: document.getElementById("error-copy"),
  footerDate: document.getElementById("footer-date"),
};

const ACCOUNT_ICONS = {
  optimized: "sparkles",
  legacy: "history",
  author: "bot",
  combined: "shield-check",
};
const ANALYTICS_NAMESPACE = "dahong-paper-snapshot";

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function numberValue(value) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function money(value, digits = 0) {
  const number = numberValue(value);
  if (number === null) {
    return "数据不足";
  }
  return `¥${number.toLocaleString("zh-CN", {
    minimumFractionDigits: digits,
    maximumFractionDigits: digits,
  })}`;
}

function signedMoney(value, digits = 0) {
  const number = numberValue(value);
  if (number === null) {
    return "数据不足";
  }
  return `${number > 0 ? "+" : ""}${money(number, digits)}`;
}

function percent(value, digits = 2) {
  const number = numberValue(value);
  if (number === null) {
    return "数据不足";
  }
  return `${number > 0 ? "+" : ""}${number.toFixed(digits)}%`;
}

function price(value) {
  const number = numberValue(value);
  if (number === null) {
    return "数据不足";
  }
  return number.toLocaleString("zh-CN", {
    minimumFractionDigits: number < 10 ? 3 : 2,
    maximumFractionDigits: 4,
  });
}

function shares(value) {
  const number = numberValue(value);
  return number === null
    ? "数据不足"
    : number.toLocaleString("zh-CN", { maximumFractionDigits: 0 });
}

function signedClass(value) {
  const number = numberValue(value);
  if (number === null || number === 0) {
    return "neutral";
  }
  return number > 0 ? "positive" : "negative";
}

function base64Bytes(value) {
  const binary = atob(String(value || ""));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

async function decryptSnapshot(envelope, password) {
  if (
    envelope?.format !== "dahong-aes-gcm-v1"
    || envelope?.kdf !== "PBKDF2-SHA256"
    || !envelope.salt
    || !envelope.iv
    || !envelope.ciphertext
  ) {
    throw new Error("加密数据格式不正确");
  }
  const material = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  const key = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: base64Bytes(envelope.salt),
      iterations: Number(envelope.iterations || 310000),
      hash: "SHA-256",
    },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"],
  );
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64Bytes(envelope.iv) },
    key,
    base64Bytes(envelope.ciphertext),
  );
  return JSON.parse(new TextDecoder().decode(plaintext));
}

async function requestPasswordAndDecrypt(envelope) {
  let lastError = null;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const password = window.prompt(
      attempt
        ? "密码不正确，请重新输入"
        : "请输入大红模拟账户访问密码",
    );
    if (password === null) {
      throw new Error("需要访问密码");
    }
    try {
      return await decryptSnapshot(envelope, password);
    } catch (error) {
      lastError = error;
    }
  }
  throw lastError || new Error("密码验证失败");
}

function accountIcon(key) {
  return ACCOUNT_ICONS[key] || "wallet-cards";
}

function shanghaiDateKey() {
  return new Intl.DateTimeFormat("en-CA", {
    timeZone: "Asia/Shanghai",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).format(new Date());
}

function accessSessionId() {
  const key = "dahong-paper-session-id";
  try {
    let value = sessionStorage.getItem(key);
    if (!value) {
      value = crypto.randomUUID
        ? crypto.randomUUID()
        : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
      sessionStorage.setItem(key, value);
    }
    return value;
  } catch {
    return null;
  }
}

function isOwnerIp(ip, config) {
  const value = String(ip || "").trim().toLowerCase();
  if (!value) {
    return null;
  }
  const exact = (config?.owner_ips || []).map(
    (item) => String(item).trim().toLowerCase(),
  );
  if (exact.includes(value)) {
    return true;
  }
  return (config?.owner_ip_prefixes || []).some((prefix) =>
    value.startsWith(String(prefix).trim().toLowerCase()),
  );
}

async function lookupIpLocation() {
  try {
    const response = await fetch("https://ipwho.is/", {
      mode: "cors",
      cache: "no-store",
      credentials: "omit",
      referrerPolicy: "no-referrer",
    });
    if (!response.ok) {
      return null;
    }
    const payload = await response.json();
    return payload?.success ? payload : null;
  } catch {
    return null;
  }
}

async function requestPreciseLocation(enabled) {
  if (!enabled || !navigator.geolocation) {
    return null;
  }
  return new Promise((resolve) => {
    let settled = false;
    const finish = (value) => {
      if (!settled) {
        settled = true;
        resolve(value);
      }
    };
    const timer = setTimeout(() => finish(null), 4500);
    navigator.geolocation.getCurrentPosition(
      (position) => {
        clearTimeout(timer);
        finish({
          latitude: position.coords.latitude,
          longitude: position.coords.longitude,
          accuracy_m: position.coords.accuracy,
          captured_at: new Date(position.timestamp).toISOString(),
          precision: "browser_gps",
        });
      },
      () => {
        clearTimeout(timer);
        finish(null);
      },
      {
        enableHighAccuracy: true,
        timeout: 4000,
        maximumAge: 600000,
      },
    );
  });
}

async function submitAccessRecord(config, record) {
  if (!config?.enabled || !config?.write_url) {
    return;
  }
  try {
    await fetch(config.write_url, {
      method: "POST",
      mode: "cors",
      cache: "no-store",
      credentials: "omit",
      referrerPolicy: "no-referrer",
      headers: { "Content-Type": "text/plain;charset=UTF-8" },
      body: JSON.stringify(record),
      keepalive: true,
    });
  } catch {
    // The page remains usable even if the private collector is unavailable.
  }
}

function trackPaperVisit(decryptedPayload) {
  const day = shanghaiDateKey();
  const sessionKey = `dahong-paper-visit:${day}`;
  try {
    if (sessionStorage.getItem(sessionKey)) {
      return;
    }
    sessionStorage.setItem(sessionKey, "1");
  } catch {
    return;
  }
  const config = decryptedPayload?.access_tracking || {};
  const counter = `daily-${day}`;
  fetch(
    `https://abacus.jasoncameron.dev/hit/${ANALYTICS_NAMESPACE}/${counter}`,
    {
      method: "GET",
      mode: "cors",
      cache: "no-store",
      credentials: "omit",
      referrerPolicy: "no-referrer",
    },
  ).catch(() => {});
  const sessionId = accessSessionId();
  void (async () => {
    const [network, preciseLocation] = await Promise.all([
      lookupIpLocation(),
      requestPreciseLocation(Boolean(config.record_precise_location)),
    ]);
    const ip = network?.ip || null;
    const ownerHint = isOwnerIp(ip, config);
    await submitAccessRecord(config, {
      schema_version: 1,
      event_type: "paper_page_unlock",
      recorded_at: new Date().toISOString(),
      day,
      session_id: sessionId,
      visitor_type: ownerHint === true
        ? "owner"
        : ownerHint === false
        ? "external"
        : "unknown",
      page: {
        url: location.href,
        path: location.pathname,
        referrer: document.referrer || null,
        title: document.title,
      },
      network: network
        ? {
            ip: network.ip,
            type: network.type,
            country: network.country,
            country_code: network.country_code,
            region: network.region,
            city: network.city,
            latitude: network.latitude,
            longitude: network.longitude,
            postal: network.postal,
            timezone: network.timezone?.id || null,
            asn: network.connection?.asn || null,
            organization: network.connection?.org || null,
            isp: network.connection?.isp || null,
          }
        : { ip: null },
      precise_location: preciseLocation,
      client: {
        user_agent: navigator.userAgent,
        language: navigator.language,
        languages: navigator.languages || [],
        platform: navigator.userAgentData?.platform || navigator.platform || null,
        viewport: {
          width: window.innerWidth,
          height: window.innerHeight,
          device_pixel_ratio: window.devicePixelRatio || 1,
        },
        screen: {
          width: window.screen?.width || null,
          height: window.screen?.height || null,
        },
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || null,
      },
    });
  })();
}

function renderOverview() {
  const accounts = state.payload.accounts || [];
  elements.overview.innerHTML = accounts.map((account) => {
    const summary = account.summary || {};
    return `
      <button
        class="account-card ${account.key === state.accountKey ? "is-active" : ""}"
        type="button"
        data-account-key="${escapeHtml(account.key)}"
        aria-pressed="${account.key === state.accountKey}"
      >
        <span class="account-card-head">
          <span>
            <strong>${escapeHtml(account.label)}</strong>
            <small>${escapeHtml(account.strategy_label || account.strategy_id || "")}</small>
          </span>
          <span class="mini-pill">${escapeHtml(account.key === "optimized" ? "待触发" : `${summary.position_count || 0} 只`)}</span>
        </span>
        <span class="account-equity">${money(summary.equity, 0)}</span>
        <span class="account-return">
          <span class="${signedClass(summary.total_return_pct)}">${percent(summary.total_return_pct)}</span>
          <small>当日 <b class="${signedClass(summary.daily_pnl)}">${signedMoney(summary.daily_pnl)}</b></small>
        </span>
      </button>
    `;
  }).join("");
}

function renderTabs() {
  elements.tabs.innerHTML = (state.payload.accounts || []).map((account) => `
    <button
      class="account-tab ${account.key === state.accountKey ? "is-active" : ""}"
      type="button"
      role="tab"
      aria-selected="${account.key === state.accountKey}"
      data-account-key="${escapeHtml(account.key)}"
    >
      <i data-lucide="${accountIcon(account.key)}"></i>
      <span>${escapeHtml(account.tab_label || account.label)}</span>
    </button>
  `).join("");
}

function activeAccount() {
  return (state.payload.accounts || []).find(
    (account) => account.key === state.accountKey,
  ) || state.payload.accounts?.[0] || {};
}

function metricHtml(label, value, note = "", tone = "") {
  return `
    <div class="metric">
      <span>${escapeHtml(label)}</span>
      <strong class="${escapeHtml(tone)}">${escapeHtml(value)}</strong>
      <small>${escapeHtml(note)}</small>
    </div>
  `;
}

function chartSvg(points) {
  const usable = (points || []).filter(
    (point) => numberValue(point.equity) !== null,
  );
  if (usable.length < 2) {
    return '<div class="empty-inline">净值曲线样本不足</div>';
  }
  const width = 760;
  const height = 220;
  const padding = { top: 16, right: 16, bottom: 24, left: 48 };
  const chartWidth = width - padding.left - padding.right;
  const chartHeight = height - padding.top - padding.bottom;
  const values = usable.map((point) => Number(point.equity));
  let min = Math.min(...values);
  let max = Math.max(...values);
  const spread = max - min || Math.max(1, max * 0.01);
  min -= spread * 0.12;
  max += spread * 0.12;
  const xFor = (index) =>
    padding.left + chartWidth * index / Math.max(1, usable.length - 1);
  const yFor = (value) =>
    padding.top + chartHeight * (1 - (value - min) / (max - min));
  const linePoints = usable.map(
    (point, index) => `${xFor(index).toFixed(2)},${yFor(Number(point.equity)).toFixed(2)}`,
  ).join(" ");
  const areaPoints = [
    `${padding.left},${padding.top + chartHeight}`,
    linePoints,
    `${padding.left + chartWidth},${padding.top + chartHeight}`,
  ].join(" ");
  const grid = [];
  for (let index = 0; index <= 4; index += 1) {
    const y = padding.top + chartHeight * index / 4;
    const value = max - (max - min) * index / 4;
    grid.push(`
      <line class="chart-grid-line" x1="${padding.left}" y1="${y}" x2="${padding.left + chartWidth}" y2="${y}"></line>
      <text class="chart-label" x="${padding.left - 7}" y="${y + 3}" text-anchor="end">${money(value, 0)}</text>
    `);
  }
  const first = usable[0];
  const last = usable[usable.length - 1];
  return `
    <svg viewBox="0 0 ${width} ${height}" role="img" aria-label="账户净值曲线">
      <defs>
        <linearGradient id="chart-fill" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="#43d68c" stop-opacity="0.23"></stop>
          <stop offset="100%" stop-color="#43d68c" stop-opacity="0"></stop>
        </linearGradient>
      </defs>
      ${grid.join("")}
      <polygon class="chart-area" points="${areaPoints}"></polygon>
      <polyline class="chart-line" points="${linePoints}"></polyline>
      <text class="chart-label" x="${padding.left}" y="${height - 5}">${escapeHtml(first.date)}</text>
      <text class="chart-label" x="${padding.left + chartWidth}" y="${height - 5}" text-anchor="end">${escapeHtml(last.date)}</text>
    </svg>
    <div class="chart-summary">
      <span>起始 <strong>${money(first.equity, 0)}</strong></span>
      <span>最新 <strong>${money(last.equity, 0)}</strong></span>
      <span>区间 <strong class="${signedClass(last.equity - first.equity)}">${signedMoney(last.equity - first.equity)}</strong></span>
    </div>
  `;
}

function positionTags(position) {
  const tags = position.tags || [];
  if (!tags.length) {
    return '<span class="tag warn">标签数据不足</span>';
  }
  return tags.map((tag) => `
    <span class="tag ${escapeHtml(tag.tone || "neutral")}">${escapeHtml(tag.text)}</span>
  `).join("");
}

function filteredPositions(account) {
  const query = state.positionQuery.trim().toLowerCase();
  const positions = account.positions || [];
  if (!query) {
    return positions;
  }
  return positions.filter((position) =>
    `${position.symbol || ""} ${position.name || ""} ${position.asset_kind_label || ""}`
      .toLowerCase()
      .includes(query),
  );
}

function positionsHtml(account) {
  const positions = filteredPositions(account);
  if (!positions.length) {
    return '<div class="empty-inline">当前筛选条件下没有模拟持仓</div>';
  }
  return `
    <div class="table-scroll positions-scroll">
      <table class="data-table">
        <thead>
          <tr>
            <th>序号</th>
            <th>证券</th>
            <th>类型</th>
            <th>持仓</th>
            <th>成本</th>
            <th>最新</th>
            <th>市值</th>
            <th>权重</th>
            <th>浮动盈亏</th>
            <th>收益率</th>
            <th>标签</th>
          </tr>
        </thead>
        <tbody>
          ${positions.map((position, index) => `
            <tr>
              <td>${index + 1}</td>
              <td>
                <div class="stock-cell">
                  <strong>${escapeHtml(`${position.symbol || ""} ${position.name || ""}`.trim())}</strong>
                  <small>${escapeHtml(position.entry_date || "建仓日期数据不足")}</small>
                </div>
              </td>
              <td>${escapeHtml(position.asset_kind_label || "股票")}</td>
              <td>${shares(position.shares)}</td>
              <td>${price(position.cost_price)}</td>
              <td>${price(position.last_price)}</td>
              <td>${money(position.market_value, 0)}</td>
              <td>${percent(position.weight_pct, 2)}</td>
              <td class="${signedClass(position.unrealized_pnl)}">${signedMoney(position.unrealized_pnl, 0)}</td>
              <td class="${signedClass(position.unrealized_pnl_pct)}">${percent(position.unrealized_pnl_pct, 2)}</td>
              <td><div class="tag-list">${positionTags(position)}</div></td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    </div>
  `;
}

function tradeRows(trades) {
  if (!trades?.length) {
    return '<div class="empty-inline">暂无成交记录</div>';
  }
  return trades.map((trade) => `
    <div class="activity-row">
      <time>${escapeHtml(String(trade.executed_at || "").replace("T", " ").slice(0, 19))}</time>
      <span><strong>${escapeHtml(`${trade.symbol || ""} ${trade.name || ""}`.trim())}</strong><small>${shares(trade.shares)} 股 · ${price(trade.price)}</small></span>
      <span class="side-pill ${trade.side === "sell" ? "sell" : "buy"}">${trade.side === "sell" ? "卖出" : "买入"}</span>
      <span class="activity-reason">${escapeHtml(trade.reason || "原因待补充")}</span>
      <span class="${signedClass(trade.realized_pnl)}">${trade.realized_pnl === null || trade.realized_pnl === undefined ? "未实现" : signedMoney(trade.realized_pnl, 0)}</span>
    </div>
  `).join("");
}

const ORDER_STATUS_LABELS = {
  pending: "待执行",
  executed: "已执行",
  skipped: "已跳过",
  cancelled: "已取消",
  corrected: "已纠错",
};

function orderRows(orders) {
  if (!orders?.length) {
    return '<div class="empty-inline">暂无订单记录</div>';
  }
  return orders.map((order) => `
    <div class="activity-row">
      <time>${escapeHtml(String(order.signal_at || order.created_at || "").replace("T", " ").slice(0, 19))}</time>
      <span><strong>${escapeHtml(`${order.symbol || ""} ${order.name || ""}`.trim())}</strong><small>${escapeHtml(order.signal_type || "")}</small></span>
      <span class="side-pill ${order.side === "sell" ? "sell" : "buy"}">${order.side === "sell" ? "卖出" : "买入"}</span>
      <span class="activity-reason">${escapeHtml(order.skip_reason || order.reason || "原因待补充")}</span>
      <span class="status-pill ${escapeHtml(order.status || "")}">${escapeHtml(ORDER_STATUS_LABELS[order.status] || order.status || "状态待补充")}</span>
    </div>
  `).join("");
}

function activityHtml(account) {
  const isOrders = state.activityMode === "orders";
  const rows = isOrders
    ? orderRows(account.recent_orders || [])
    : tradeRows(account.recent_trades || []);
  return `
    <section class="panel activity-panel">
      <div class="panel-head">
        <div>
          <h3>最近成交与订单审计</h3>
          <p>${isOrders ? "最近订单，包含待执行、跳过与纠错状态" : "最近模拟成交，已计入费用"}</p>
        </div>
        <div class="activity-tabs">
          <button class="activity-tab ${isOrders ? "" : "is-active"}" type="button" data-activity-mode="trades">最近成交</button>
          <button class="activity-tab ${isOrders ? "is-active" : ""}" type="button" data-activity-mode="orders">订单审计</button>
        </div>
      </div>
      <div class="activity-list">${rows}</div>
    </section>
  `;
}

function renderAccount() {
  const account = activeAccount();
  if (!account.key) {
    elements.view.innerHTML = '<div class="loading-panel">没有可展示的模拟账户</div>';
    return;
  }
  const summary = account.summary || {};
  const metrics = [
    metricHtml("账户权益", money(summary.equity, 0), `初始 ${money(account.initial_cash, 0)}`),
    metricHtml("累计收益", percent(summary.total_return_pct, 2), signedMoney(summary.total_pnl, 0), signedClass(summary.total_return_pct)),
    metricHtml("当日盈亏", signedMoney(summary.daily_pnl, 0), percent(summary.daily_return_pct, 2), signedClass(summary.daily_pnl)),
    metricHtml("持仓市值", money(summary.market_value, 0), `${summary.position_count || 0} 个持仓`),
    metricHtml("可用现金", money(summary.cash, 0), "模拟账户现金"),
    metricHtml("待执行", String(summary.pending_order_count || 0), `${summary.trade_count || 0} 笔累计成交`, Number(summary.pending_order_count) ? "warn" : ""),
  ].join("");
  elements.view.innerHTML = `
    <article class="account-panel">
      <header class="account-header">
        <div>
          <h2>${escapeHtml(account.label)}</h2>
          <p>${escapeHtml(account.strategy_label || "")} · ${escapeHtml(account.strategy_id || "")}</p>
        </div>
        <span class="account-badge"><i data-lucide="${accountIcon(account.key)}"></i>模拟账户</span>
      </header>
      <div class="metric-grid">${metrics}</div>
      <div class="dashboard-grid">
        <section class="panel">
          <div class="panel-head">
            <div>
              <h3>账户净值曲线</h3>
              <p>每个收盘快照的模拟权益</p>
            </div>
          </div>
          <div class="chart-wrap">${chartSvg(account.equity_curve || [])}</div>
        </section>
        <section class="panel">
          <div class="panel-head">
            <div>
              <h3>账户摘要</h3>
              <p>已实现与浮动盈亏分开记录</p>
            </div>
          </div>
          <div class="metric-grid" style="grid-template-columns:repeat(2,minmax(0,1fr));">
            ${metricHtml("已实现盈亏", signedMoney(summary.realized_pnl, 0), "已平仓部分", signedClass(summary.realized_pnl))}
            ${metricHtml("浮动盈亏", signedMoney(summary.unrealized_pnl, 0), "当前持仓", signedClass(summary.unrealized_pnl))}
            ${metricHtml("累计成交", String(summary.trade_count || 0), "笔")}
            ${metricHtml("已平仓", String(summary.closed_trade_count || 0), "笔")}
          </div>
        </section>
      </div>
      <section class="panel positions-panel">
        <div class="panel-head">
          <div>
            <h3>当前模拟持仓</h3>
            <p>${escapeHtml(account.label)} · 共 ${(account.positions || []).length} 只</p>
          </div>
          <div class="panel-tools">
            <label class="search-box">
              <i data-lucide="search"></i>
              <input id="position-search" type="search" value="${escapeHtml(state.positionQuery)}" placeholder="搜索代码、名称或类型" autocomplete="off">
            </label>
          </div>
        </div>
        ${positionsHtml(account)}
      </section>
      ${activityHtml(account)}
    </article>
  `;
  window.lucide?.createIcons({ attrs: { "stroke-width": 1.8 } });
}

function renderAll() {
  const payload = state.payload;
  elements.asOf.textContent = payload.as_of || "日期不足";
  elements.generatedAt.textContent = `快照生成 ${String(payload.generated_at || "").replace("T", " ").slice(0, 19)}`;
  elements.footerDate.textContent = `${payload.as_of || "日期不足"} · ${payload.accounts?.length || 0} 套模拟账户`;
  elements.statusTitle.textContent = `数据已更新至 ${payload.as_of || "未知日期"}`;
  renderOverview();
  renderTabs();
  renderAccount();
  window.lucide?.createIcons({ attrs: { "stroke-width": 1.8 } });
}

function bindEvents() {
  document.addEventListener("click", (event) => {
    const accountButton = event.target.closest("[data-account-key]");
    if (accountButton) {
      state.accountKey = accountButton.dataset.accountKey;
      state.positionQuery = "";
      renderOverview();
      renderTabs();
      renderAccount();
      window.lucide?.createIcons();
      return;
    }
    const activityButton = event.target.closest("[data-activity-mode]");
    if (activityButton) {
      state.activityMode = activityButton.dataset.activityMode;
      renderAccount();
    }
  });
  document.addEventListener("input", (event) => {
    if (event.target.id === "position-search") {
      state.positionQuery = event.target.value;
      const account = activeAccount();
      const tablePanel = event.target.closest(".positions-panel");
      if (tablePanel) {
        const scroll = tablePanel.querySelector(".table-scroll, .empty-inline");
        if (scroll) {
          scroll.outerHTML = positionsHtml(account);
        }
      }
    }
  });
}

async function load() {
  try {
    const cacheBuster = Date.now();
    let payload;
    const encryptedResponse = await fetch(
      `./data/paper-accounts.enc.json?v=${cacheBuster}`,
      { cache: "no-store" },
    );
    if (encryptedResponse.ok) {
      payload = await requestPasswordAndDecrypt(
        await encryptedResponse.json(),
      );
    } else {
      const response = await fetch(
        `./data/paper-accounts.json?v=${cacheBuster}`,
        { cache: "no-store" },
      );
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      payload = await response.json();
    }
    if (payload.status !== "ok" || !payload.accounts?.length) {
      throw new Error(payload.error || "公开快照为空");
    }
    state.payload = payload;
    state.accountKey = payload.accounts.some(
      (account) => account.key === "combined",
    )
      ? "combined"
      : payload.accounts[0].key;
    renderAll();
    trackPaperVisit(payload);
  } catch (error) {
    elements.errorPanel.hidden = false;
    elements.errorCopy.textContent = error.message || String(error);
    elements.statusTitle.textContent = "公开快照读取失败";
    elements.view.innerHTML = '<div class="loading-panel">无法读取公开账户数据</div>';
    window.lucide?.createIcons();
  }
}

bindEvents();
load();
