// Comparaison entre deux audits (snapshot A "avant" / snapshot B "après").
//
// Sortie :
//   - score_diff   : { before, after, delta }
//   - improvements : contrôles dont le statut s'est amélioré (severité ↓)
//   - regressions  : contrôles dont le statut s'est dégradé (severité ↑)
//   - unchanged    : contrôles dont le statut est identique
//
// On utilise un rang de sévérité pour traiter toutes les transitions de
// manière uniforme — fail→pass est une amélioration, mais aussi fail→warn ;
// pass→warn est une régression, tout comme warn→fail.
const SEVERITY = { pass: 0, na: 0, warn: 1, fail: 2 }

const buildEntry = (before, after) => ({
  control_id: before.control_id,
  title: before.title,
  domain: before.domain,
  cis_level: before.cis_level,
  status_before: before.status,
  status_after: after.status,
  actual_before: before.actual_value,
  actual_after: after.actual_value
})

export const compareAudits = (auditA, auditB) => {
  const empty = {
    score_diff: { before: 0, after: 0, delta: 0 },
    improvements: [],
    regressions: [],
    unchanged: []
  }
  if (!auditA || !auditB) return empty

  // Indexation par control_id pour matcher les contrôles entre A et B
  const indexA = new Map(auditA.results.map(c => [c.control_id, c]))
  const indexB = new Map(auditB.results.map(c => [c.control_id, c]))

  const improvements = []
  const regressions = []
  const unchanged = []

  // Union des deux ensembles ; un contrôle absent d'un côté est ignoré
  // pour cette première itération (à raffiner quand on aura des snapshots
  // versionnés où la liste des contrôles peut évoluer entre versions).
  const allIds = new Set([...indexA.keys(), ...indexB.keys()])

  allIds.forEach(controlId => {
    const before = indexA.get(controlId)
    const after = indexB.get(controlId)
    if (!before || !after) return

    const rankBefore = SEVERITY[before.status] ?? 0
    const rankAfter = SEVERITY[after.status] ?? 0
    const entry = buildEntry(before, after)

    if (rankAfter < rankBefore) improvements.push(entry)
    else if (rankAfter > rankBefore) regressions.push(entry)
    else unchanged.push(entry)
  })

  return {
    score_diff: {
      before: auditA.score_global,
      after: auditB.score_global,
      delta: auditB.score_global - auditA.score_global
    },
    improvements,
    regressions,
    unchanged
  }
}
