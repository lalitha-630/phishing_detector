  const HISTORY_KEY = 'phishguard_scan_history_v1';
  const HISTORY_LIMIT = 10;

  function loadHistory() {
    try {
      const raw = localStorage.getItem(HISTORY_KEY);
      const parsed = raw ? JSON.parse(raw) : [];
      return Array.isArray(parsed) ? parsed : [];
    } catch (_) {
      return [];
    }
  }

  function saveHistory(items) {
    try {
      localStorage.setItem(HISTORY_KEY, JSON.stringify(items));
    } catch (_) {}
  }

  function renderHistory() {
    const list = document.getElementById('historyList');
    if (!list) return;

    const items = loadHistory();
    const noResults = document.getElementById('noHistoryResults');
    if (!items.length) {
      if (noResults) noResults.style.display = 'block';
      list.innerHTML = '';
      return;
    }
    
    if (noResults) noResults.style.display = 'none';

    list.innerHTML = items.map((item, i) => {
      const risk = String(item.risk_level || 'Unknown').toUpperCase();
      const status = String(item.status || '');
      const conf = String(item.confidence || '');
      const isPhish = status.toLowerCase().includes('phishing');
      const date = item.ts ? new Date(item.ts).toLocaleString() : 'Unknown';
      return `<tr>
        <td>${date}</td>
        <td class="url-cell">${item.url || ''}</td>
        <td class="label-cell">
          <span class="badge ${isPhish ? 'phish' : 'legit'}">${status}</span>
        </td>
        <td class="label-cell">${conf}</td>
      </tr>`;
    }).join('');
  }

  function addToHistory(payload) {
    const url = String(payload.url || '').trim();
    if (!url) return;

    const riskStr = String(payload.risk_level || 'Unknown');
    const risk = riskStr.toLowerCase();
    const isPhishing = !!payload.is_phishing;
    const tone = isPhishing ? (risk.includes('high') ? 'danger' : 'medium') : 'safe';

    const next = [
      {
        url,
        status: payload.status || (isPhishing ? 'Phishing' : 'Legitimate'),
        risk_level: riskStr,
        confidence: payload.confidence || '',
        tone,
        ts: Date.now(),
      },
      ...loadHistory().filter(x => x && x.url !== url),
    ].slice(0, HISTORY_LIMIT);

    saveHistory(next);
    renderHistory();
  }

  function clearHistory() {
    try { localStorage.removeItem(HISTORY_KEY); } catch (_) {}
    renderHistory();
  }

  function showPage(name) {
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
    document.getElementById('page-' + name).classList.add('active');
    document.getElementById('tab-' + name).classList.add('active');
    window.scrollTo(0, 0);
    
    if (name === 'dataset') {
      fetchDataset();
    }
  }

  /** Must match FastAPI POST endpoint (see app.py). */
  const API = 'http://localhost:8000/predict';

  document.getElementById('urlInput').addEventListener('keydown', e => {
    if (e.key === 'Enter') scanURL();
  });

  document.getElementById('clearHistoryBtn')?.addEventListener('click', clearHistory);
  renderHistory();

  async function scanURL() {
    const url = document.getElementById('urlInput').value.trim();
    if (!url) return;

    document.getElementById('resultCard').classList.remove('show');
    document.getElementById('errorMsg').classList.remove('show');
    document.getElementById('loading').classList.add('show');
    document.getElementById('scanBtn').disabled = true;

    try {
      const res = await fetch(API, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
      });
      if (!res.ok) {
        let detail = '';
        try {
          const errBody = await res.json();
          detail = errBody.detail ? String(errBody.detail) : JSON.stringify(errBody);
        } catch (_) {
          detail = await res.text();
        }
        throw new Error(detail || `Server error: ${res.status}`);
      }
      const data = await res.json();
      showResult(data);
    } catch (err) {
      showError(err.message.includes('fetch')
        ? 'Cannot connect to API. Make sure the server is running on localhost:8000'
        : err.message
      );
    } finally {
      document.getElementById('loading').classList.remove('show');
      document.getElementById('scanBtn').disabled = false;
    }
  }

  function showResult(data) {
    const isPhishing = !!data.is_phishing;
    const riskStr = String(data.risk_level || 'Unknown');
    const risk = riskStr.toLowerCase();
    let tone = isPhishing ? (risk.includes('high') ? 'danger' : 'medium') : 'safe';

    const header = document.getElementById('resultHeader');
    header.className = 'result-header ' + tone;

    const status = document.getElementById('resultStatus');
    status.textContent = (data.status || (isPhishing ? 'Phishing' : 'Legitimate'));
    status.className = 'result-status ' + tone;

    let confStr = String(data.confidence ?? '');
    if (confStr && !confStr.includes('%')) confStr = confStr + '%';

    const badge = document.getElementById('confidenceBadge');
    badge.textContent = (confStr || '—') + ' confidence';
    badge.className = 'confidence-badge ' + tone;

    const pct = Number(String(confStr).replace('%', ''));
    const fill = document.getElementById('confidenceFill');
    if (fill && Number.isFinite(pct)) {
      fill.className = 'confidence-fill ' + tone;
      fill.style.width = Math.max(0, Math.min(100, pct)) + '%';
    } else if (fill) {
      fill.className = 'confidence-fill ' + tone;
      fill.style.width = '0%';
    }

    document.getElementById('urlDisplay').textContent = data.url || '';

    const pillTone = tone;
    document.getElementById('riskSummary').innerHTML =
      '<span class="risk-pill ' + pillTone + '">Risk: ' + riskStr + '</span>' +
      '<span class="risk-meta">Verdict: <strong>' + (data.status || '—') + '</strong> · Model confidence: <strong>' + (confStr || '—') + '</strong></span>';

    const f = data.features_summary || {};
    const numSub = Number(f.num_subdomains);
    const urlLen = Number(f.url_length);
    const susp = Number(f.suspicious_keywords);
    const lookalike = !!f.is_lookalike_domain || Number(f.brand_similarity_score) >= 0.82 || !!f.brand_obfuscated_match;
    const items = [
      { name: 'HTTPS',            val: !!f.is_https,                    good: true,  label: f.is_https ? 'Yes' : 'No' },
      { name: 'IP Address',       val: !!f.has_ip_address,             good: false, label: f.has_ip_address ? 'Detected' : 'None' },
      { name: '@ Symbol',         val: !!f.has_at_symbol,              good: false, label: f.has_at_symbol ? 'Found' : 'None' },
      { name: 'Hyphen in Domain', val: !!f.has_hyphen_domain,          good: false, label: f.has_hyphen_domain ? 'Yes' : 'No' },
      { name: 'Subdomains',       val: numSub > 2,                     good: false, label: Number.isFinite(numSub) ? numSub : '—' },
      { name: 'Suspicious Words', val: susp > 0,                       good: false, label: Number.isFinite(susp) ? susp : '—' },
      { name: 'URL Length',       val: urlLen > 75,                    good: false, label: (Number.isFinite(urlLen) ? urlLen : '—') + ' chars' },
      { name: 'Lookalike Domain', val: lookalike,                       good: false, label: lookalike ? 'Detected' : 'None' },
      { name: 'Risk Level',       val: null,                           good: null,  label: riskStr, neutral: true },
    ];

    const grid = document.getElementById('featuresGrid');
    grid.innerHTML = items.map(item => {
      let cls = 'neutral';
      if (!item.neutral) {
        if (item.good) cls = item.val ? 'ok' : 'bad';
        else cls = item.val ? 'bad' : 'ok';
      }
      return `<div class="feature-item">
        <span class="feature-name">${item.name}</span>
        <span class="feature-val ${cls}">${item.label}</span>
      </div>`;
    }).join('');

    // Eye-catching alert near risk header (cyber theme)
    // Only show if lookalike AND not explicitly marked as Safe
    if (lookalike && tone !== 'safe') {
      document.getElementById('riskSummary').insertAdjacentHTML(
        'beforeend',
        ' <span class="lookalike-alert"><span class="chip">ALERT</span><span>Lookalike / Typosquatting Detected</span></span>'
      );
    }

    document.getElementById('resultCard').classList.add('show');
    addToHistory(data);
  }

  function showError(msg) {
    const el = document.getElementById('errorMsg');
    el.textContent = '! Error: ' + msg;
    el.classList.add('show');
  }

  /* ─── DATASET ─── */
  let DATASET = [];
  let datasetLoaded = false;

  async function fetchDataset() {
    if (datasetLoaded) return;
    
    document.getElementById('datasetLoading').style.display = 'block';
    document.getElementById('datasetTableWrap').style.display = 'none';
    
    try {
      const res = await fetch('http://localhost:8000/api/dataset');
      if (!res.ok) throw new Error('Failed to fetch dataset');
      DATASET = await res.json();
      datasetLoaded = true;
      
      const legitCount = DATASET.filter(r => r[1] === 0).length;
      const phishCount = DATASET.filter(r => r[1] === 1).length;
      document.getElementById('totalCount').textContent = DATASET.length;
      document.getElementById('legitCount').textContent = legitCount;
      document.getElementById('phishCount').textContent = phishCount;
      
      setFilter('all');
      document.getElementById('datasetTableWrap').style.display = 'block';
    } catch (err) {
      console.error(err);
      alert('Error loading dataset. Make sure backend is running.');
    } finally {
      document.getElementById('datasetLoading').style.display = 'none';
    }
  }

  let currentFilter = 'all';

  function setFilter(f) {
    currentFilter = f;
    document.querySelectorAll('.filter-btn').forEach(b => b.className = 'filter-btn');
    if (f === 'all')   document.getElementById('btn-all').classList.add('active-all');
    if (f === 'legit') document.getElementById('btn-legit').classList.add('active-legit');
    if (f === 'phish') document.getElementById('btn-phish').classList.add('active-phish');
    applyFilters();
  }

  function applyFilters() {
    const query = document.getElementById('searchInput').value.toLowerCase();
    const tbody = document.getElementById('tableBody');
    const noResults = document.getElementById('noResults');

    let filtered = DATASET.filter(([url, label]) => {
      const matchFilter =
        currentFilter === 'all' ||
        (currentFilter === 'legit' && label === 0) ||
        (currentFilter === 'phish' && label === 1);
      return matchFilter && url.toLowerCase().includes(query);
    });

    tbody.innerHTML = filtered.map(([url, label], i) => `
      <tr>
        <td>${i + 1}</td>
        <td class="url-cell">${url}</td>
        <td class="label-cell">
          <span class="badge ${label === 0 ? 'legit' : 'phish'}">
            ${label === 0 ? 'Legitimate' : 'Phishing'}
          </span>
        </td>
      </tr>
    `).join('');

    noResults.style.display = filtered.length === 0 ? 'block' : 'none';
    document.getElementById('rowCount').innerHTML =
      `Showing <span>${filtered.length}</span> of <span>${DATASET.length}</span> URLs`;
  }

  setFilter('all');
  showPage('scanner');