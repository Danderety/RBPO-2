from common import *

def js_checks():
 for filename in ['vulnerable.js','fixed.js']:
  v=filename=='vulnerable.js';part=4 if v else 5
  import socket
  with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
  env=os.environ.copy();env['PORT']=str(port)
  log=tempfile.TemporaryFile(mode='w+')
  proc=subprocess.Popen(['node',filename],cwd=R/'projects/javascript',env=env,stdout=log,stderr=log)
  base=f'http://127.0.0.1:{port}'
  try:
   for _ in range(100):
    try:http(client(),base+'/hello?name=ready');break
    except (OSError,urllib.error.URLError):
     if proc.poll() is not None:raise RuntimeError('Node server exited')
     time.sleep(.05)
   else:raise RuntimeError('Node server not ready')
   for name,value in [('sqli',"' OR 1=1 --"),('sqli-normal','alice'),('sqli-negative','absent')]:
    response=http(client(),base+'/user?'+urllib.parse.urlencode({'username':value}));row=json.loads(response['body'])
    ok=(isinstance(row,dict) and row.get('username')=='admin') if name=='sqli' and v else row is None if name in ['sqli','sqli-negative'] else isinstance(row,dict) and row.get('username')=='alice'
    record(part,filename+'-'+name,response['status']==200 and ok,response)
   payload='<script>window.RBPO_XSS=1</script>';response=http(client(),base+'/hello?'+urllib.parse.urlencode({'name':payload}))
   record(part,filename+'-xss',(payload in response['body'])==v and (v or '&lt;script&gt;' in response['body']),{'response':response,'scope':'HTML output only'})
   response=http(client(),base+'/ping?'+urllib.parse.urlencode({'host':'127.0.0.1; printf RBPO_CMD'}))
   record(part,filename+'-command',('RBPO_CMD' in response['body']) if v else response['status']==400 and 'RBPO_CMD' not in response['body'],response)
   response=http(client(),base+'/hello?name=Alice')
   record(part,filename+'-hello-normal','Hello, Alice!' in response['body'],response)
  finally:
   proc.terminate()
   try:proc.wait(timeout=5)
   except subprocess.TimeoutExpired:proc.kill();proc.wait()
   log.seek(0);save(part,filename+'-server.log',log.read());log.close()
