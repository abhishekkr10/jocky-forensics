from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.auth import create_user
from backend.app import engine,rulepacks

def test_publish_pinned_yara_pack_and_detect_preserved_bytes():
    with TestClient(app) as client:
        create_user('pack-admin','Test-pack-password-123')
        login=client.post('/api/v1/auth/login',json={'username':'pack-admin','password':'Test-pack-password-123'})
        client.headers['X-CSRF-Token']=login.json()['csrf']
        published=client.post('/api/v1/rule-packs',json={'engine':'yara','version':'2.0.0','source':'rule custom_marker { strings: $a = "JOCKY" nocase condition: $a }'})
        assert published.status_code==201,published.text
        pack=published.json()['id']
        assert any(item['id']==pack for item in client.get('/api/v1/rule-packs').json())
        bundle=engine.run(f'mode lab\ncollect files as f\nscan yara "{pack}" on f as d\nverify evidence','custom-pack','custom-case')
        assert bundle['plan']['rule_digests'][pack]==published.json()['digest']
        assert bundle['detections'][0]['rule_pack_version']=='2.0.0'
        assert bundle['verification']['integrity']=='valid'
        path=rulepacks.path_for(pack)
        original=path.read_text()
        path.write_text(original.replace('2.0.0','3.0.0'))
        try:
            import pytest
            with pytest.raises(ValueError,match='digest'):rulepacks.load(pack)
        finally:path.write_text(original)

def test_sigma_publication_and_reviewer_restriction():
    from backend.app.core import ROOT
    with TestClient(app) as client:
        create_user('sigma-pack-admin','Test-pack-password-123')
        login=client.post('/api/v1/auth/login',json={'username':'sigma-pack-admin','password':'Test-pack-password-123'})
        client.headers['X-CSRF-Token']=login.json()['csrf']
        publication=client.post('/api/v1/rule-packs',json={'engine':'sigma','version':'2.0.0','source':(ROOT/'rules/sigma/encoded_script.yml').read_text()})
        assert publication.status_code==201,publication.text
        pack=publication.json()['id']
        bundle=engine.run(f'mode lab\ncollect event_logs as e\nhunt sigma "{pack}" on e as d\nverify evidence','sigma-pack-test','sigma-pack-case')
        assert any(d['rule_pack_id']==pack for d in bundle['detections'])
        client.post('/api/v1/auth/logout',json={})
        create_user('pack-reviewer','Test-pack-password-123','reviewer')
        login=client.post('/api/v1/auth/login',json={'username':'pack-reviewer','password':'Test-pack-password-123'})
        client.headers['X-CSRF-Token']=login.json()['csrf']
        assert client.post('/api/v1/rule-packs',json={'engine':'yara','version':'1.0.0','source':'rule test { condition: true }'}).status_code==403
