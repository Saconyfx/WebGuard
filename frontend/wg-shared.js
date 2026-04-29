/* ============================================================
   WebGuard — Shared scan utilities
   Used by url-scan.html, file-upload.html, code-review.html
   ============================================================ */

window.WG = (function () {
  'use strict';

  const $ = (s) => document.querySelector(s);
  const $$ = (s) => document.querySelectorAll(s);

  function showFieldError(el, msg) {
    el.textContent = msg;
    el.classList.add('form-error--visible');
  }
  function hideFieldError(el) {
    el.classList.remove('form-error--visible');
    el.textContent = '';
  }

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  function formatBytes(b) {
    if (b < 1024) return b + ' B';
    if (b < 1024 * 1024) return (b / 1024).toFixed(1) + ' KB';
    return (b / 1024 / 1024).toFixed(2) + ' MB';
  }

  // Stage runner — drives the progress block
  function runStages(stages, refs, done) {
    let i = 0;
    function next() {
      if (i >= stages.length) { setTimeout(done, 260); return; }
      const s = stages[i];
      refs.label.textContent = s.label;
      refs.fill.style.width = s.pct + '%';
      refs.pct.textContent = s.pct + '%';

      if (refs.stepEls && s.step) {
        refs.stepEls.forEach((el) => {
          if (el.dataset.step === s.step) el.classList.add('step--active');
        });
        if (i > 0 && stages[i - 1].step) {
          refs.stepEls.forEach((el) => {
            if (el.dataset.step === stages[i - 1].step) {
              el.classList.remove('step--active');
              el.classList.add('step--done');
            }
          });
        }
      }
      i++;
      setTimeout(next, 480);
    }
    next();
  }

  // Universal results renderer
  // Stores last results for export
  let _lastResults = null;

  function renderResults({ source, findings, tools_run, tools_failed, scan_seconds }) {
    const resultsSection = $('#results-section');
    const resultsBody = $('#results-body');
    const resultsMeta = $('#results-meta');
    const sevSummary = $('#severity-summary');
    if (!resultsSection || !resultsBody) return;

    _lastResults = { source, findings, tools_run, tools_failed, scan_seconds, scanned_at: new Date().toISOString() };

    let metaParts = ['Completed just now', escapeHtml(source)];
    if (typeof scan_seconds === 'number') metaParts.push(scan_seconds.toFixed(2) + 's');
    if (Array.isArray(tools_run) && tools_run.length) metaParts.push('via ' + tools_run.join(', '));
    if (Array.isArray(tools_failed) && tools_failed.length) metaParts.push('failed: ' + tools_failed.join(', '));
    resultsMeta.innerHTML = metaParts.join(' &middot; ');

    const counts = { critical: 0, high: 0, med: 0, low: 0, info: 0, clean: 0 };
    findings.forEach((f) => { counts[f.sev] = (counts[f.sev] || 0) + 1; });

    const sevOrder = ['critical', 'high', 'med', 'low', 'info', 'clean'];
    const sevLabels = { critical: 'Critical', high: 'High', med: 'Medium', low: 'Low', info: 'Info', clean: 'Clean' };

    sevSummary.innerHTML = sevOrder.filter((k) => counts[k])
      .map((k) => `<span class="sev-chip sev-chip--${k}"><span class="sev-chip__count">${counts[k]}</span> ${sevLabels[k]}</span>`)
      .join('');

    resultsBody.innerHTML = findings.map((f, i) => {
      const sevLabel = (sevLabels[f.sev] || f.sev).toUpperCase();
      const hasSnippet = f.code_snippet && Array.isArray(f.code_snippet.lines) && f.code_snippet.lines.length > 0;
      const rowId = 'finding-' + i;

      return `
      <tr class="finding-row${hasSnippet ? ' finding-row--expandable' : ''}"
          data-row-id="${rowId}"${hasSnippet ? ' role="button" tabindex="0" aria-expanded="false"' : ''}>
        <td class="row-num">${String(i + 1).padStart(2, '0')}</td>
        <td><span class="sev-badge sev-badge--${f.sev}">${sevLabel}</span></td>
        <td class="cell-line">${f.line ? escapeHtml(String(f.line)) : '<span class="cell-line--empty">—</span>'}</td>
        <td>${escapeHtml(f.cat)}</td>
        <td class="cell-finding">${escapeHtml(f.finding)}</td>
        <td class="cell-code">${escapeHtml(f.code)}</td>
        <td class="cell-tool">${f.tool ? escapeHtml(f.tool) : '—'}</td>
        <td class="cell-status">
          <span class="status-badge ${f.status === 'New' ? 'status-badge--new' : ''}">${escapeHtml(f.status)}</span>
          ${hasSnippet ? '<span class="row-toggle" aria-hidden="true">▸</span>' : ''}
        </td>
      </tr>
      ${hasSnippet ? `
        <tr class="snippet-row" id="${rowId}-snippet" hidden>
          <td colspan="8">
            ${_buildSnippetHTML(f)}
          </td>
        </tr>
      ` : ''}
      `;
    }).join('');

    resultsSection.hidden = false;
    resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });

    _bindExportButtons();
    _bindRowExpand();
    _highlightAll();
  }

  // ── Snippet HTML ─────────────────────────────────────
  function _buildSnippetHTML(f) {
    const snip = f.code_snippet;
    const lang = snip.language || 'plaintext';
    const startLine = snip.start_line;
    const vulnLine = snip.vulnerable_line;

    const numberedRows = snip.lines.map((rawLine, idx) => {
      const lineNum = startLine + idx;
      const isVuln = lineNum === vulnLine;
      // We escape here because Prism highlights code that we'll set as innerHTML
      return `<div class="snippet-line${isVuln ? ' snippet-line--vuln' : ''}">
        <span class="snippet-num">${lineNum}</span>
        <code class="snippet-code language-${escapeHtml(lang)}">${escapeHtml(rawLine || ' ')}</code>
      </div>`;
    }).join('');

    return `
      <div class="snippet-block">
        <div class="snippet-block__head">
          <span class="snippet-block__icon">📄</span>
          <span class="snippet-block__title">Vulnerable code · line ${vulnLine}</span>
          <span class="snippet-block__lang">${escapeHtml(lang)}</span>
          <button class="snippet-block__copy" data-copy-snippet>Copy</button>
        </div>
        <div class="snippet-block__body">
          ${numberedRows}
        </div>
        <div class="snippet-block__footer">
          <span class="snippet-block__rule">${escapeHtml(f.code)}</span>
          <span class="snippet-block__sep">·</span>
          <span class="snippet-block__tool">flagged by ${escapeHtml(f.tool || 'scanner')}</span>
        </div>
      </div>
    `;
  }

  // ── Row expand/collapse ──────────────────────────────
  function _bindRowExpand() {
    const rows = document.querySelectorAll('.finding-row--expandable');
    rows.forEach((row) => {
      if (row._bound) return;
      row._bound = true;
      const toggle = () => {
        const id = row.dataset.rowId + '-snippet';
        const snip = document.getElementById(id);
        if (!snip) return;
        const open = !snip.hidden;
        snip.hidden = open;
        row.classList.toggle('finding-row--open', !open);
        row.setAttribute('aria-expanded', String(!open));
      };
      row.addEventListener('click', (e) => {
        // Don't toggle when clicking copy button etc. inside snippet
        if (e.target.closest('[data-copy-snippet]')) return;
        toggle();
      });
      row.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle(); }
      });
    });

    // Copy snippet handler
    document.querySelectorAll('[data-copy-snippet]').forEach((btn) => {
      if (btn._bound) return;
      btn._bound = true;
      btn.addEventListener('click', async (e) => {
        e.stopPropagation();
        const block = btn.closest('.snippet-block');
        if (!block) return;
        const codeEls = block.querySelectorAll('.snippet-code');
        const text = Array.from(codeEls).map((el) => el.textContent).join('\n');
        try {
          await navigator.clipboard.writeText(text);
          const orig = btn.textContent;
          btn.textContent = '✓ Copied';
          setTimeout(() => { btn.textContent = orig; }, 1200);
        } catch (_) {
          btn.textContent = '✗ Failed';
        }
      });
    });
  }

  // ── PrismJS syntax highlighting ──────────────────────
  function _highlightAll() {
    if (typeof window.Prism === 'undefined') return;
    document.querySelectorAll('.snippet-code').forEach((el) => {
      try { window.Prism.highlightElement(el); } catch (_) { /* swallow */ }
    });
  }

  // ── Export handlers ──────────────────────────────────
  function _bindExportButtons() {
    const jsonBtn = $('#export-json');
    const pdfBtn = $('#export-pdf');
    const copyBtn = $('#copy-clipboard');

    if (jsonBtn && !jsonBtn._bound) {
      jsonBtn._bound = true;
      jsonBtn.addEventListener('click', exportJSON);
    }
    if (pdfBtn && !pdfBtn._bound) {
      pdfBtn._bound = true;
      pdfBtn.addEventListener('click', exportPDF);
    }
    if (copyBtn && !copyBtn._bound) {
      copyBtn._bound = true;
      copyBtn.addEventListener('click', copyToClipboard);
    }
  }

  function _filenameStem() {
    if (!_lastResults) return 'webguard-scan';
    // Try to extract filename from "File scan · app.py"
    const m = (_lastResults.source || '').match(/[·:]\s*(.+?)$/);
    const name = m ? m[1].trim() : 'scan';
    const ts = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    return `webguard-${name.replace(/[^\w.-]/g, '_')}-${ts}`;
  }

  function _downloadBlob(content, filename, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  function exportJSON() {
    if (!_lastResults) return;
    const content = JSON.stringify(_lastResults, null, 2);
    _downloadBlob(content, _filenameStem() + '.json', 'application/json');
  }

  async function exportPDF() {
    if (!_lastResults) return;
    const btn = $('#export-pdf');
    const original = btn ? btn.textContent : null;
    if (btn) { btn.textContent = 'Building...'; btn.disabled = true; }
    try {
      // Build the payload the backend expects (matches the ScanResponse shape).
      const payload = {
        source: _lastResults.source,
        findings: _lastResults.findings,
        tools_run: _lastResults.tools_run || [],
        tools_failed: _lastResults.tools_failed || [],
        scan_seconds: _lastResults.scan_seconds || 0,
      };
      const resp = await fetch('/report/pdf', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      if (!resp.ok) {
        let msg = 'PDF generation failed (HTTP ' + resp.status + ')';
        try { const err = await resp.json(); if (err.detail) msg = err.detail; } catch (_) {}
        throw new Error(msg);
      }
      const blob = await resp.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = _filenameStem() + '.pdf';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (e) {
      alert('PDF export failed: ' + e.message);
    } finally {
      if (btn) { btn.textContent = original; btn.disabled = false; }
    }
  }

  async function copyToClipboard() {
    if (!_lastResults) return;
    const btn = $('#copy-clipboard');
    const original = btn.textContent;
    try {
      await navigator.clipboard.writeText(JSON.stringify(_lastResults, null, 2));
      btn.textContent = '✓ Copied';
      setTimeout(() => { btn.textContent = original; }, 1500);
    } catch (e) {
      btn.textContent = '✗ Failed';
      setTimeout(() => { btn.textContent = original; }, 1500);
    }
  }

  function hideResults() {
    const r = $('#results-section');
    if (r) r.hidden = true;
  }

  return {
    $, $$, showFieldError, hideFieldError, escapeHtml, formatBytes,
    runStages, renderResults, hideResults,
  };
})();
