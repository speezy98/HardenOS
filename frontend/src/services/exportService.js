// Service d'export d'un rapport d'audit HardenOS.
//
// Les fonctions consomment le rapport assemblé par le backend
// (GET /api/reports/<audit_id>) : { system, audit, summary { score_global,
// risk_level, scores_by_domain, counts }, controls[] avec remediation }.
//
// JSON, CSV et HTML sont générés côté client (Blob + lien <a download>).
// Le HTML est un document AUTONOME (styles dans une balise <style>, aucune
// dépendance à l'app) : imprimable proprement via le navigateur
// (Imprimer -> Enregistrer en PDF), ce qui couvre le besoin PDF sans export dédié.
//
// Toutes les fonctions sont pures sauf downloadFile (téléchargement navigateur).

const APP_VERSION = '0.1.0'

// Aplatit la remediation (objet { type, script } ou null) en texte pour le CSV.
const remediationText = (rem) => {
  if (!rem) return ''
  if (typeof rem === 'string') return rem
  return rem.script || ''
}

// Échappement CSV : entoure de guillemets si la valeur contient virgule,
// guillemet ou saut de ligne, et double les guillemets internes.
const escapeCSV = (val) => {
  if (val === null || val === undefined) return ''
  const s = String(val)
  if (/[",\n\r]/.test(s)) {
    return `"${s.replace(/"/g, '""')}"`
  }
  return s
}

// Structure JSON du rapport : meta + system + audit + summary + controls.
// `report` est la réponse de GET /api/reports/<audit_id> (source de vérité).
export const generateJSON = (report) => {
  if (!report) return null

  return {
    meta: {
      generator: 'HardenOS',
      version: APP_VERSION,
      generated_at: new Date().toISOString()
    },
    system: report.system,
    audit: report.audit,
    summary: {
      score_global: report.summary.score_global,
      risk_level: report.summary.risk_level,
      scores_by_domain: report.summary.scores_by_domain || {},
      counts: report.summary.counts
    },
    controls: report.controls.map((c) => ({
      control_id: c.control_id,
      title: c.title,
      domain: c.domain,
      cis_level: c.cis_level,
      weight: c.weight,
      status: c.status,
      expected_value: c.expected_value,
      actual_value: c.actual_value,
      remediation: c.remediation || null
    }))
  }
}

// CSV : en-tête + une ligne par contrôle (remediation aplatie en texte).
export const generateCSV = (report) => {
  if (!report) return ''

  const { system } = report
  const headers = [
    'control_id',
    'title',
    'domain',
    'cis_level',
    'weight',
    'status',
    'expected_value',
    'actual_value',
    'remediation',
    'system_hostname',
    'system_os'
  ]

  const lines = [headers.join(',')]

  report.controls.forEach((c) => {
    const row = [
      c.control_id,
      c.title,
      c.domain,
      c.cis_level,
      c.weight,
      c.status,
      c.expected_value,
      c.actual_value,
      remediationText(c.remediation),
      system.hostname,
      `${system.os_type} ${system.os_version}`
    ].map(escapeCSV)
    lines.push(row.join(','))
  })

  return lines.join('\n')
}

// --- Export HTML (document autonome, imprimable) ----------------------------

// Échappe le texte pour une insertion sûre dans le HTML (évite toute injection
// depuis un titre/valeur/script de contrôle).
const escapeHTML = (val) => {
  if (val === null || val === undefined) return ''
  return String(val)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

const DOMAIN_LABELS = {
  access: 'Accès', network: 'Réseau', logging: 'Journalisation',
  crypto: 'Chiffrement', updates: 'Mises à jour', services: 'Services'
}

const STATUS_LABELS = {
  pass: 'Conforme', fail: 'Non conforme', warn: 'Avertissement', na: 'Non vérifiable'
}

const RISK_LABELS = {
  low: 'Faible', moderate: 'Modéré', high: 'Élevé', critical: 'Critique'
}

const formatDateFR = (iso) => {
  if (!iso) return '—'
  const d = new Date(iso)
  return isNaN(d) ? '—' : d.toLocaleString('fr-FR')
}

const remediationHTML = (rem) => {
  const script = rem && (typeof rem === 'string' ? rem : rem.script)
  if (!script) {
    return '<p class="rem-none">Aucune remédiation automatique documentée pour ce contrôle.</p>'
  }
  return `<pre class="rem-script">${escapeHTML(script)}</pre>`
}

// Une carte HTML par contrôle non conforme (observé / attendu / remédiation).
const failCardHTML = (c) => `
      <article class="fail-card">
        <div class="fail-head"><span class="cid">${escapeHTML(c.control_id)}</span> ${escapeHTML(c.title)}</div>
        <div class="diff">
          <div class="diff-cell diff-bad"><span class="diff-lbl">Observé</span><span class="diff-val">${escapeHTML(c.actual_value) || '—'}</span></div>
          <div class="diff-cell diff-good"><span class="diff-lbl">Attendu</span><span class="diff-val">${escapeHTML(c.expected_value) || '—'}</span></div>
        </div>
        <div class="rem"><span class="rem-lbl">Recommandation de remédiation</span>${remediationHTML(c.remediation)}</div>
      </article>`

// Une ligne de tableau pour les contrôles secondaires (pass/warn/na).
const controlRowHTML = (c) =>
  `<tr><td class="cid">${escapeHTML(c.control_id)}</td><td>${escapeHTML(c.title)}</td>` +
  `<td>${escapeHTML(DOMAIN_LABELS[c.domain] || c.domain)}</td>` +
  `<td class="st st-${escapeHTML(c.status)}">${escapeHTML(STATUS_LABELS[c.status] || c.status)}</td></tr>`

const secondarySection = (title, controls) => {
  if (!controls.length) return ''
  const rows = controls.map(controlRowHTML).join('')
  return `
    <section class="block">
      <h2>${escapeHTML(title)} (${controls.length})</h2>
      <table class="ctrl-table">
        <thead><tr><th>ID</th><th>Contrôle</th><th>Domaine</th><th>Statut</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </section>`
}

// Document HTML complet et autonome à partir du rapport backend.
export const generateHTML = (report) => {
  if (!report) return ''

  const { system, audit, summary, controls } = report
  const counts = summary.counts || { pass: 0, fail: 0, warn: 0, na: 0, total: 0 }
  const score = summary.score_global != null ? Math.round(summary.score_global) : '—'
  const risk = summary.risk_level
  const riskLabel = risk ? (RISK_LABELS[risk] || risk) : '—'
  const generatedAt = new Date().toLocaleString('fr-FR')

  const byStatus = (s) => controls.filter((c) => c.status === s)
  const fails = byStatus('fail')
  const warns = byStatus('warn')
  const passes = byStatus('pass')
  const nas = byStatus('na')

  // Barres de domaine en HTML/CSS pur (pas de JS de graphe -> imprimable).
  const domainRows = Object.keys(DOMAIN_LABELS)
    .filter((k) => summary.scores_by_domain && k in summary.scores_by_domain)
    .map((k) => {
      const v = summary.scores_by_domain[k]
      const pct = v == null ? 0 : v
      const band = pct >= 80 ? 'good' : pct >= 60 ? 'mid' : 'bad'
      return `
        <tr>
          <td class="dom-name">${escapeHTML(DOMAIN_LABELS[k])}</td>
          <td class="dom-bar-cell"><div class="dom-bar"><div class="dom-fill dom-${band}" style="width:${pct}%"></div></div></td>
          <td class="dom-val">${v == null ? '—' : v}</td>
        </tr>`
    })
    .join('')

  const failsSection = fails.length
    ? fails.map(failCardHTML).join('')
    : '<p class="all-good">Aucune non-conformité détectée.</p>'

  return `<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Rapport de conformité HardenOS — ${escapeHTML(system.hostname)}</title>
<style>
  :root { --fail:#c0392b; --pass:#2e7d32; --warn:#b8860b; --ink:#1a1a1a; --muted:#666; --line:#ddd; }
  * { box-sizing: border-box; }
  body { font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color: var(--ink); margin: 0; padding: 32px; max-width: 900px; margin: 0 auto; line-height: 1.5; }
  h1 { font-size: 24px; margin: 0 0 4px; }
  h2 { font-size: 17px; margin: 0 0 12px; border-bottom: 2px solid var(--ink); padding-bottom: 4px; }
  .sub { color: var(--muted); font-size: 13px; margin: 0; }
  .doc-head { border-bottom: 3px solid var(--ink); padding-bottom: 16px; margin-bottom: 24px; }
  .identity { margin-top: 12px; font-size: 14px; }
  .identity strong { display: inline-block; min-width: 130px; color: var(--muted); font-weight: 600; }
  .block { margin-bottom: 28px; }

  /* Verdict */
  .verdict { display: flex; align-items: center; gap: 32px; flex-wrap: wrap; }
  .score-box { text-align: center; border: 3px solid var(--ink); border-radius: 12px; padding: 16px 24px; min-width: 130px; }
  .score-num { font-size: 44px; font-weight: 700; line-height: 1; }
  .score-unit { font-size: 13px; color: var(--muted); }
  .risk { font-size: 15px; }
  .risk .badge { display: inline-block; padding: 2px 10px; border-radius: 4px; font-weight: 700; border: 1px solid; }
  .risk-low { color: var(--pass); border-color: var(--pass); }
  .risk-moderate { color: var(--warn); border-color: var(--warn); }
  .risk-high, .risk-critical { color: var(--fail); border-color: var(--fail); }

  /* Compteurs */
  .counts { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 16px; }
  .count { border: 1px solid var(--line); border-radius: 8px; padding: 8px 14px; text-align: center; min-width: 90px; }
  .count .n { font-size: 22px; font-weight: 700; }
  .count .l { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: .5px; }
  .count-pass .n { color: var(--pass); }
  .count-fail .n { color: var(--fail); }
  .count-warn .n { color: var(--warn); }

  /* Domaines */
  table { border-collapse: collapse; width: 100%; font-size: 13px; }
  .dom-table td { padding: 6px 8px; vertical-align: middle; }
  .dom-name { width: 130px; font-weight: 600; }
  .dom-val { width: 40px; text-align: right; font-variant-numeric: tabular-nums; font-weight: 700; }
  .dom-bar { background: #eee; border-radius: 4px; height: 14px; overflow: hidden; border: 1px solid var(--line); }
  .dom-fill { height: 100%; }
  .dom-good { background: var(--pass); }
  .dom-mid { background: var(--warn); }
  .dom-bad { background: var(--fail); }

  /* Non-conformités */
  .fail-card { border: 1px solid var(--line); border-left: 4px solid var(--fail); border-radius: 6px; padding: 12px 14px; margin-bottom: 14px; }
  .fail-head { font-size: 14px; font-weight: 600; margin-bottom: 8px; }
  .cid { font-family: "SF Mono", Menlo, Consolas, monospace; font-size: 12px; color: var(--muted); margin-right: 6px; }
  .diff { display: flex; gap: 10px; margin-bottom: 8px; }
  .diff-cell { flex: 1; border: 1px solid var(--line); border-radius: 4px; padding: 6px 8px; }
  .diff-lbl { display: block; font-size: 10px; text-transform: uppercase; letter-spacing: .5px; color: var(--muted); }
  .diff-val { font-family: "SF Mono", Menlo, Consolas, monospace; font-size: 12px; word-break: break-word; }
  .diff-bad { background: #fbeeee; }
  .diff-good { background: #eef7ee; }
  .rem-lbl { display: block; font-size: 10px; text-transform: uppercase; letter-spacing: .5px; color: var(--fail); font-weight: 700; margin-bottom: 4px; }
  .rem-script { background: #f6f6f6; border: 1px solid var(--line); border-radius: 4px; padding: 8px; font-family: "SF Mono", Menlo, Consolas, monospace; font-size: 12px; white-space: pre-wrap; word-break: break-word; margin: 0; }
  .rem-none { font-size: 12px; color: var(--muted); font-style: italic; margin: 0; }
  .all-good { color: var(--pass); font-weight: 600; }

  /* Tableaux secondaires */
  .ctrl-table th, .ctrl-table td { border: 1px solid var(--line); padding: 5px 8px; text-align: left; }
  .ctrl-table th { background: #f4f4f4; font-size: 12px; }
  .st { font-weight: 600; }
  .st-pass { color: var(--pass); }
  .st-warn { color: var(--warn); }
  .st-na { color: var(--muted); }
  .st-fail { color: var(--fail); }

  .footer { margin-top: 32px; padding-top: 12px; border-top: 1px solid var(--line); font-size: 11px; color: var(--muted); }
  .print-hint { background: #eef4ff; border: 1px solid #cdd; border-radius: 6px; padding: 10px 14px; font-size: 13px; margin-bottom: 20px; }

  @media print {
    body { padding: 0; max-width: none; }
    .print-hint { display: none; }
    /* Pas de fonds gourmands en encre : on garde uniquement bordures + texte. */
    .diff-bad, .diff-good, .rem-script, .ctrl-table th, .count, .dom-bar { background: transparent !important; }
    .dom-fill { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
    .fail-card { page-break-inside: avoid; }
    .block { page-break-inside: avoid; }
    h2 { page-break-after: avoid; }
    tr { page-break-inside: avoid; }
  }
</style>
</head>
<body>
  <p class="print-hint">Astuce : utilisez <strong>Imprimer → Enregistrer en PDF</strong> pour obtenir la version PDF de ce rapport.</p>

  <header class="doc-head">
    <h1>Rapport de conformité HardenOS</h1>
    <p class="sub">Référentiel CIS Benchmark — niveau ${escapeHTML(audit.cis_level)}</p>
    <div class="identity">
      <div><strong>Machine</strong> ${escapeHTML(system.hostname)}</div>
      <div><strong>Adresse IP</strong> ${escapeHTML(system.ip_address)}</div>
      <div><strong>Système</strong> ${escapeHTML(system.os_type)} — ${escapeHTML(system.os_version)}</div>
      <div><strong>Date de l'audit</strong> ${escapeHTML(formatDateFR(audit.finished_at || audit.created_at))}</div>
      <div><strong>Audit</strong> #${escapeHTML(audit.id)}</div>
    </div>
  </header>

  <section class="block">
    <h2>Synthèse</h2>
    <div class="verdict">
      <div class="score-box">
        <div class="score-num">${score}</div>
        <div class="score-unit">/ 100</div>
      </div>
      <div class="risk">
        Niveau de risque : <span class="badge risk-${escapeHTML(risk || 'low')}">${escapeHTML(riskLabel)}</span>
      </div>
    </div>
    <div class="counts">
      <div class="count count-pass"><div class="n">${counts.pass}</div><div class="l">Conformes</div></div>
      <div class="count count-fail"><div class="n">${counts.fail}</div><div class="l">Non conformes</div></div>
      <div class="count count-warn"><div class="n">${counts.warn}</div><div class="l">Avertissements</div></div>
      <div class="count"><div class="n">${counts.na}</div><div class="l">Non vérifiables</div></div>
      <div class="count"><div class="n">${counts.total}</div><div class="l">Total</div></div>
    </div>
  </section>

  <section class="block">
    <h2>Scores par domaine</h2>
    <table class="dom-table">${domainRows}</table>
  </section>

  <section class="block">
    <h2>Non-conformités à corriger (${fails.length})</h2>
    ${failsSection}
  </section>

  ${secondarySection('Avertissements', warns)}
  ${secondarySection('Contrôles conformes', passes)}
  ${secondarySection('Contrôles non vérifiables', nas)}

  <footer class="footer">
    Généré par HardenOS v${APP_VERSION} le ${escapeHTML(generatedAt)} — document autonome, imprimable en PDF.
  </footer>
</body>
</html>`
}

// Déclenche le téléchargement client via Blob + ancre temporaire.
export const downloadFile = (content, filename, mimeType) => {
  const blob = new Blob([content], { type: mimeType })
  const url = URL.createObjectURL(blob)

  const link = document.createElement('a')
  link.href = url
  link.download = filename
  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)

  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

// Taille en octets d'une string UTF-8 (Blob pour précision).
export const estimateSize = (content) => {
  if (!content) return { bytes: 0, formatted: '0 B' }
  const bytes = new Blob([content]).size
  return { bytes, formatted: formatBytes(bytes) }
}

const formatBytes = (bytes) => {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
}

// Nom de fichier conventionnel et stable :
// hardenos_<host>_<timestamp>.<ext>
export const buildFilename = (system, ext) => {
  const ts = new Date().toISOString().replace(/[:T]/g, '-').slice(0, 16)
  const host = (system?.hostname || 'audit').replace(/[^a-zA-Z0-9_-]/g, '_')
  return `hardenos_${host}_${ts}.${ext}`
}
