"""Removed email detection must not be reachable through any active assessment API."""
from unittest.mock import patch
import pytest
from test_platform import system,post,data,asset

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
