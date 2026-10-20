export default function AdvisoryCoverage({coverage}) {
  if(!coverage)return null;
  return <p className="fine" role="status">Advisory grouping: {coverage.completed}/{coverage.total} records checked · {coverage.grouped_matches} overlapping reports grouped.
    {coverage.status==='partial'?' Detail lookup is incomplete; remaining matches are kept separately and may overlap.':' Grouping uses OSV alias relationships for the same exact package.'}
    {' '}This is separate from package assessment coverage and does not establish exploitability.
    {coverage.severity&&<> CVSS ratings: {coverage.severity.scored}/{coverage.severity.total} grouped matches have a usable base rating
      {coverage.severity.partial>0?`; ${coverage.severity.partial} have incomplete rating evidence`:''}. Missing ratings remain unknown.</>}</p>;
}
