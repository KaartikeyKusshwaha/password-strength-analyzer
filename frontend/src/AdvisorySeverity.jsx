export default function AdvisorySeverity({finding}) {
  if(finding?.rule!=='DEP001')return null;
  const assessment=finding.severity_assessment;
  if(!assessment?.selected)return <div className="notice" role="status">CVSS rating unavailable. This advisory match is retained; missing severity does not mean low risk. Run a new check to request current advisory details.</div>;
  const selected=assessment.selected;
  return <section className="panel" aria-label="Advisory severity">
    <h3>Reported advisory severity</h3>
    <p><strong>{selected.base_score.toFixed(1)} / 10 · {selected.rating} · CVSS {selected.version} base</strong></p>
    <p>From OSV record <a href={'https://osv.dev/vulnerability/'+encodeURIComponent(selected.advisory)} target="_blank" rel="noreferrer">{selected.advisory}</a>
      {selected.declared_source?` · source declared by record: ${selected.declared_source}`:'. No separate rating source declared.'}</p>
    <p className="fine">{assessment.scored_advisories}/{assessment.total_advisories} matched advisory records have usable ratings.
      {assessment.status==='partial'?' Rating coverage is incomplete.':''}
      {' '}This is the highest available category, then score. CVSS versions are not interchangeable risk scales; this does not measure exposure or prove exploitability on your system.</p>
    <details><summary>Rating evidence ({assessment.ratings.length})</summary>
      {assessment.ratings.map((rating,index)=><article className="spaced" key={index}>
        <p><strong>{rating.advisory}</strong> · CVSS {rating.version} base {rating.base_score.toFixed(1)} · {rating.rating}
          {rating.declared_source?` · declared source: ${rating.declared_source}`:''}</p>
        <p className="fine">Base vector: <code style={{overflowWrap:'anywhere'}}>{rating.vector}</code></p>
        {rating.reported_vector!==rating.vector&&<p className="fine">Reported vector: <code style={{overflowWrap:'anywhere'}}>{rating.reported_vector}</code>. Optional threat, temporal or environmental metrics are excluded from the displayed base score.</p>}
      </article>)}
      {assessment.ignored_ratings>0&&<p className="fine">{assessment.ignored_ratings} invalid or ambiguous ratings/entries were ignored.</p>}
      {assessment.truncated&&<p className="fine">Rating evidence exceeded the bounded lookup/display limit; this is a partial view.</p>}
    </details>
  </section>;
}
