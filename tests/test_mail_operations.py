"""Removed email detection must not be reachable through any active assessment API."""
from unittest.mock import patch
import pytest
from test_platform import system,post,data,asset
from backend.store import Store,uid

@pytest.mark.parametrize('format',['text','eml'])
def test_retired_email_detection_is_rejected_without_queueing_or_storing_input(system,format):
    app,client,_=system
    identifier=asset(client)['id'];workspace=client.get('/api/me').json()['workspace']
    private='private-retired-message-do-not-store'
    with patch.object(app.state.executor,'submit') as worker:
        operation=post(client,'/operations',{'action':'email','content':private,'email_format':format,'authorized':True})
        scan=post(client,'/scans',{'kind':'email','asset_id':identifier,'label':'Retired request','content':private,'authorized':True})
        review=post(client,'/security-reviews',{'workspace_id':workspace,'name':'Retired request','authorized':True,'checks':[{'action':'email','content':private,'authorized':True}]})
    assert [r.status_code for r in (operation,scan,review)]==[422,422,422]
    assert not worker.called
    value=data(client)
    assert not value['operations'] and not value['scans'] and not value['security_reviews']


def test_retired_findings_never_infer_a_fix_from_an_unrelated_historical_recheck(system):
    app,client,_=system;me=client.get('/api/me').json();finding,job,scan=uid(),uid(),uid()
    old={'scan_id':'old-scan','asset_id':'old-asset','kind':'email','label':'Historical submission','message_digest':'old-message'}
    with app.state.store.connect(write=True) as c:
        Store.put(c,me['workspace'],'findings',{'id':finding,**old,'rule':'MAIL001','status':'open'})
        Store.put(c,me['workspace'],'scans',{'id':scan,**old,'message_digest':'different-message','status':'complete','finding_ids':[]})
        Store.put(c,me['workspace'],'jobs',{'id':job,'status':'complete','created_by':me['id'],'finding_ids':[finding],'snapshot':{finding:old}})
    result=post(client,'/agents/'+job+'/progress',{})
    assert result.status_code==200,result.text
    assert result.json()['checks'][0]['state']=='unavailable'
    assert result.json()['checks'][0]['scan_id'] is None
