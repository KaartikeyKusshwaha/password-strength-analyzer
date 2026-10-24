import json
import os
import time
from unittest.mock import Mock
import pytest
from companion.helper_client import Pairing,CLOUD_ORIGIN,protect,save_connection,load_connection

def connection():return {'server':CLOUD_ORIGIN,'token':'x'*54,'allowed_targets':['127.0.0.1','::1'],'allow_posture':True,'allow_updates':False}

def test_proof_never_appears_in_url_and_changed_scope_is_rejected():
    requester=Mock(side_effect=[{'id':'a'*24,'server':CLOUD_ORIGIN,'pairing_code':'ABCD2345','expires':time.time()+300},{'status':'approved','connection':{**connection(),'allow_updates':True}}])
    pairing=Pairing('Windows helper',True,False,requester);pairing.start()
    assert len(pairing.proof)==43 and all(pairing.proof not in args[0] for args,kw in requester.call_args_list)
    with pytest.raises(ValueError,match='scope changed'):pairing.poll()

@pytest.mark.skipif(os.name!='nt',reason='Real Windows DPAPI is required')
def test_real_dpapi_storage_roundtrip_and_wrong_blob_rejected(tmp_path):
    value=connection();path=tmp_path/'connection.dpapi'
    save_connection(path,value)
    assert value['token'].encode() not in path.read_bytes() and path.read_bytes()!=json.dumps(value).encode()
    assert load_connection(path)==value
    with pytest.raises(ValueError):protect(b'not-dpapi',decrypt=True)

def test_storage_rejects_wider_or_changed_server_scope(tmp_path):
    for value in [{**connection(),'allowed_targets':['192.168.1.1']},{**connection(),'server':'https://other.example'}]:
        with pytest.raises(ValueError,match='Unexpected helper scope'):save_connection(tmp_path/'connection',value,protector=lambda v:v)
