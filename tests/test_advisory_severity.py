import pytest

from backend.advisory_severity import assess, parse_rating, record_ratings
from backend.advisories import enrich
from test_advisories import item, provider

V2='AV:N/AC:L/Au:N/C:C/I:C/A:C'
V3='CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'
V4='CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:N'
PACKAGE={'ecosystem':'PyPI','name':'example-pkg','version':'1.0.0'}


def rating(vector=V3,kind='CVSS_V3',source=None):
    return {'type':kind,'score':vector,'source':source}


@pytest.mark.parametrize('kind,vector,score,level',[
    ('CVSS_V2',V2,10.0,'high'),
    ('CVSS_V3',V3,9.8,'critical'),
    ('CVSS_V3',V3.replace('3.1','3.0'),9.8,'critical'),
    ('CVSS_V4',V4,9.9,'critical'),
    ('CVSS_V3','CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N',0.0,'none'),
])
def test_known_cvss_base_vectors(kind,vector,score,level):
    value=parse_rating(rating(vector,kind,'NVD'),'GHSA-fixture')
    assert (value['base_score'],value['rating'],value['declared_source'])==(score,level,'NVD')
    assert value['vector']==vector and value['advisory']=='GHSA-fixture'


@pytest.mark.parametrize('kind,vector,optional',[
    ('CVSS_V2',V2,'/E:U/RL:OF/RC:UC'),
    ('CVSS_V3',V3,'/E:U/RL:O/RC:U/CR:L'),
    ('CVSS_V4',V4,'/E:U/CR:L/IR:L/AR:L/MAV:P'),
])
def test_optional_metrics_are_validated_but_do_not_change_the_base_score(kind,vector,optional):
    full=parse_rating(rating(vector+optional,kind),'A')
    base=parse_rating(rating(vector,kind),'A')
    assert full is not None
    assert full['base_score']==base['base_score'] and full['vector']==vector
    assert full['reported_vector']==vector+optional
    assert parse_rating(rating(vector+'/INVALID:H',kind),'A') is None


@pytest.mark.parametrize('value',[
    None,[],False,'CRITICAL',{}, {'type':[],'score':V3},{'type':{},'score':V3},
    rating(9.8),rating('9.8'),rating(V3,'CVSS_V4'),rating(V4,'CVSS_V3'),
    rating(V3,'unknown'),rating(V3+'/AV:L'),rating(V3.replace('/AV:N','')),
    rating(V3+'\n'),rating(V3+'<script>'),rating('a'*1025),
])
def test_untrusted_or_malformed_ratings_do_not_become_scores(value):
    assert parse_rating(value,'A') is None


@pytest.mark.parametrize('source',[[],{},False,'https://evil.test/','NVD\n'])
def test_invalid_source_is_not_echoed_or_used_as_an_identity(source):
    assert parse_rating(rating(source=source),'A')['declared_source'] is None


def test_grouped_ratings_preserve_sources_and_rank_category_before_incomparable_generations():
    records={'A':{'id':'A','severity':[rating(V2,'CVSS_V2','NVD')]},
             'B':{'id':'B','severity':[rating(source='CNA'),rating(source='SELF'),rating(source='CNA')]}}
    result=assess(['A','B'],records,PACKAGE)
    assert result['status']=='available' and result['scored_advisories']==2
    assert result['selected']['base_score']==9.8 and result['selected']['rating']=='critical'
    assert len(result['ratings'])==3
    assert {r['declared_source'] for r in result['ratings']}=={'NVD','CNA','SELF'}


def test_missing_invalid_and_bounded_ratings_cannot_clear_a_match():
    records={'A':{'id':'A','severity':[rating(),rating('9.8')]}}
    result=assess(['A','B'],records,PACKAGE)
    assert result['status']=='partial' and result['scored_advisories']==1 and result['ignored_ratings']==1
    assert assess(['B'],records,PACKAGE)['status']=='unavailable'
    records['A']['severity']=[rating()]*9
    assert assess(['A'],records,PACKAGE)['truncated']
    many={str(i):{'id':str(i),'severity':[rating()]} for i in range(21)}
    result=assess(list(many),many,PACKAGE)
    assert result['truncated'] and result['status']=='partial' and len(result['ratings'])==20


def test_package_specific_ratings_cannot_leak_from_another_package_or_ecosystem():
    rows=[{'package':{'ecosystem':'PyPI','name':'EXAMPLE_pkg'},'severity':[rating()]},
          {'package':{'ecosystem':'PyPI','name':'other'},'severity':[rating(V4,'CVSS_V4')]},
          {'package':{'ecosystem':'npm','name':'example-pkg'},'severity':[rating(V2,'CVSS_V2')]}]
    values,ignored,truncated=record_ratings({'id':'A','affected':rows},PACKAGE)
    assert len(values)==1 and values[0]['version']=='3.1' and not ignored and not truncated
    assert record_ratings({'id':'A','affected':rows[1:]},PACKAGE)[0]==[]
    assert record_ratings({'id':'A','affected':rows,'severity':[rating()]},PACKAGE)[0]==[]


def test_ambiguous_affected_entries_require_explicit_version_membership():
    rows=[{'package':PACKAGE,'versions':['1.0.0'],'severity':[rating()]},
          {'package':PACKAGE,'ranges':[{'type':'ECOSYSTEM','events':[{'introduced':'0'}]}],'severity':[rating(V4,'CVSS_V4')]}]
    result=assess(['A'],{'A':{'id':'A','affected':rows}},PACKAGE)
    assert result['selected']['version']=='3.1' and result['status']=='partial' and result['ignored_ratings']==1
    rows[0]['versions']=['2.0.0']
    assert assess(['A'],{'A':{'id':'A','affected':rows}},PACKAGE)['selected'] is None


@pytest.mark.parametrize('field,value',[('severity',{}),('severity',None),('affected',{}),('affected',[None]),('affected',[{}]*101)])
def test_malformed_record_fields_are_unavailable(field,value):
    result=assess(['A'],{'A':{'id':'A',field:value}},PACKAGE)
    assert result['status']=='unavailable' and result['ignored_ratings']>=1


def test_enrichment_exposes_scoring_coverage_separately_from_alias_lookup():
    records={'A':{'id':'A','aliases':['B'],'severity':[rating()]},
             'B':{'id':'B','aliases':['A']},'C':{'id':'C','severity':[rating('9.8')]}}
    result,coverage=enrich([item('A'),item('B'),item('C')],provider(records))
    assert len(result)==2 and result[0]['severity']=='critical' and result[1]['severity']=='unknown'
    assert coverage['completed']==3 and coverage['status']=='complete'
    assert coverage['severity']=={'total':2,'scored':1,'partial':1}
    assert result[0]['severity_assessment']['total_advisories']==2
    assert result[0]['severity_assessment']['status']=='partial'
