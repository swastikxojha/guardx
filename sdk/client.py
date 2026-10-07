import httpx
class GuardXResult:
    def __init__(self,data): self._data=data
    def __getattr__(self,k): return self._data.get(k)
    def __repr__(self): return repr(self._data)
class GuardX:
    def __init__(self,api_key,base_url="http://127.0.0.1:8000/api/v1"): self.base_url=base_url.rstrip('/');self.headers={"X-API-Key":api_key}
    def _post(self,path,payload):
        r=httpx.post(self.base_url+path,json=payload,headers=self.headers,timeout=20);r.raise_for_status();return GuardXResult(r.json())
    def check_input(self,content,**kwargs): return self._post('/check/input',{"content":content,**kwargs})
    def check_output(self,content,**kwargs): return self._post('/check/output',{"content":content,**kwargs})
    def check_action(self,tool,parameters=None,**kwargs): return self._post('/check/action',{"tool":tool,"parameters":parameters or {},**kwargs})
