"""Exercise the real prototype foundation, including a persistence restart."""
import hashlib
import http.cookiejar
import json
import ssl
import urllib.request
import urllib.error

from prototype import PRIVATE, compose, run

def snapshot():
    config=json.loads((PRIVATE/'users.json').read_text(encoding='utf-8'))
    user=next(u for u in config['users'] if u['actor_id']=='user:sec-lead-1')
    context=ssl.create_default_context(cafile=str(PRIVATE/'ca.pem'))
    client=urllib.request.build_opener(urllib.request.HTTPSHandler(context=context),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    origin=config['origin']
    body=json.dumps({'tenant_id':config['tenant_id'],'actor_id':user['actor_id'],'password':user['password']}).encode()
    request=urllib.request.Request(origin+'/api/auth/login',data=body,headers={'Content-Type':'application/json','Origin':origin})
    with client.open(request,timeout=20) as response:
        if response.status!=200:raise RuntimeError('real password login failed')
    with client.open(origin+'/api/console/bootstrap',timeout=10) as response:graph=json.load(response)
    if graph['scope']!='ORGANIZATION':raise RuntimeError('investigator scope unavailable')
    if len(graph['nodes'])<10 or len(graph['edges'])<10:raise RuntimeError('real simulator organization absent')
    with client.open(origin+'/readyz',timeout=10) as response:
        if not json.load(response)['ready']:raise RuntimeError('unready core')
    public=compose('exec','-T','core','cat','/data/core/identity.json',capture_output=True).stdout
    return {'graph_version':graph['graph_version'],'nodes':len(graph['nodes']),'edges':len(graph['edges']),'identity_sha256':hashlib.sha256(public).hexdigest(),'origin':origin}

def main():
    before=snapshot()
    run(['python','scripts/prototype.py','restart','--no-build'])
    after=snapshot()
    if before!=after:raise RuntimeError('restart changed trusted identity, source cut or graph')
    # A stopped database must never remain a healthy decision service.
    compose('stop','postgres')
    try:
        context=ssl.create_default_context(cafile=str(PRIVATE/'ca.pem'))
        try:
            urllib.request.urlopen('https://localhost:8444/readyz',context=context,timeout=10)
            raise RuntimeError('core reported ready without database')
        except urllib.error.HTTPError as error:
            if error.code!=503:raise
    finally:
        compose('up','-d','--wait','postgres')
    result={'before':before,'after':after,'restart_preserved':True,'database_outage_refused':True}
    (PRIVATE/'foundation-evidence.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(result,indent=2))

if __name__=='__main__':main()
