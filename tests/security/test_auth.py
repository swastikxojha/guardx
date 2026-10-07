def test_invalid_token(client):
    r=client.post('/api/v1/check/input',headers={'Authorization':'Bearer nope'},json={'content':'hi'});assert r.status_code==401

def test_cross_org_isolation(client):
    r=client.post('/api/v1/auth/signup',json={'email':'other@example.com','password':'StrongPass123!','organization_name':'Other Org'});assert r.status_code==200
    token=r.json()['access_token'];h={'Authorization':'Bearer '+token}
    # The second org must not see the first org's request list.
    rows=client.get('/api/v1/audit/requests',headers=h);assert rows.status_code==200;assert rows.json()==[]
