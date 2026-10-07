from uuid import uuid4


def test_api_key_and_action(client):
    r=client.post('/api/v1/auth/signup',json={'email':'key@example.com','password':'StrongPass123!','organization_name':'Key Org'})
    assert r.status_code==200
    token=r.json()['access_token']; h={'Authorization':'Bearer '+token}
    k=client.post('/api/v1/api-keys',headers=h,json={'name':'integration','scopes':['guard:check']})
    assert k.status_code==200
    listed=client.get('/api/v1/api-keys',headers=h)
    assert listed.status_code==200
    assert all('key_hash' not in row for row in listed.json())
    raw=k.json()['api_key']; x=client.post('/api/v1/check/action',headers={'X-API-Key':raw},json={'tool':'send_email','parameters':{'recipient':'external@example.com','body':'customer database export'}})
    assert x.status_code==200
    assert x.json()['decision']=='BLOCK'
    revoked=client.post('/api/v1/api-keys/'+k.json()['id']+'/revoke',headers=h)
    assert revoked.status_code==200
    assert client.post('/api/v1/check/input',headers={'X-API-Key':raw},json={'content':'revoked key'}).status_code==401


def test_api_key_expiry_and_tenant_scope(client):
    email_a=f'key-a-{uuid4().hex}@example.test'
    email_b=f'key-b-{uuid4().hex}@example.test'
    token_a=client.post('/api/v1/auth/signup',json={'email':email_a,'password':'StrongPass123!','organization_name':'Key Org A'}).json()['access_token']
    token_b=client.post('/api/v1/auth/signup',json={'email':email_b,'password':'StrongPass123!','organization_name':'Key Org B'}).json()['access_token']
    headers_a={'Authorization':'Bearer '+token_a}
    headers_b={'Authorization':'Bearer '+token_b}
    app_a=client.post('/api/v1/applications',headers=headers_a,json={'name':'app-a'}).json()['id']
    app_b=client.post('/api/v1/applications',headers=headers_b,json={'name':'app-b'}).json()['id']

    bound=client.post('/api/v1/api-keys',headers=headers_a,json={'name':'bound','application_id':app_a,'scopes':['guard:check']})
    assert bound.status_code==200
    key=bound.json()['api_key']
    check=client.post('/api/v1/check/input',headers={'X-API-Key':key},json={'content':'bounded request'})
    assert check.status_code==200
    detail=client.get('/api/v1/audit/requests/'+check.json()['request_id'],headers=headers_a).json()
    assert detail['request']['application_id']==app_a
    assert client.post('/api/v1/check/input',headers={'X-API-Key':key},json={'content':'wrong app','application_id':app_b}).status_code==403
    org_key=client.post('/api/v1/api-keys',headers=headers_a,json={'name':'org-wide','scopes':['guard:check']}).json()['api_key']
    assert client.post('/api/v1/check/input',headers={'X-API-Key':org_key},json={'content':'foreign app','application_id':app_b}).status_code==404
    assert client.post('/api/v1/api-keys',headers=headers_a,json={'name':'foreign-app','application_id':app_b}).status_code==404
    policy_b=client.post('/api/v1/policies',headers=headers_b,json={'name':'private-policy','rules':[{'category':'private','action':'BLOCK'}]}).json()['id']
    assert client.post('/api/v1/check/input',headers={'X-API-Key':org_key},json={'content':'foreign policy','policy_id':policy_b}).status_code==404

    expired=client.post('/api/v1/api-keys',headers=headers_a,json={'name':'expired','expires_at':'2020-01-01T00:00:00Z'})
    assert expired.status_code==200
    assert client.post('/api/v1/check/input',headers={'X-API-Key':expired.json()['api_key']},json={'content':'expired key'}).status_code==401
    assert client.post('/api/v1/api-keys',headers=headers_a,json={'name':'invalid-date','expires_at':'not-a-date'}).status_code==422
