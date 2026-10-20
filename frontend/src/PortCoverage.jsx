export default function PortCoverage({observations}) {
  if(!Array.isArray(observations)||!observations.length)return null;
  const assessed=observations.filter(o=>o.status==='open'||o.status==='closed').length;
  return <section className="spaced"><h3>TCP port coverage</h3><p>{assessed}/{observations.length} selected ports assessed. {observations.length-assessed} unassessed.</p><table><thead><tr><th>Target</th><th>TCP port</th><th>Observed state</th></tr></thead><tbody>{observations.map((o,i)=><tr key={i}><td>{o.host}</td><td>{o.port}</td><td>{o.status==='open'?'Open':o.status==='closed'?'Connection refused (closed)':'Unassessed'}</td></tr>)}</tbody></table><p className="fine">A successful connection does not identify the service or prove vulnerability or public exposure. Refused and unassessed connections do not certify safety.</p></section>;
}
