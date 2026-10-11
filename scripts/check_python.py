from common import *

def python_checks():
 from werkzeug.serving import make_server
 for variant in ['vulnmart','fixed']:
  spec=importlib.util.spec_from_file_location('lab_'+variant,R/f'projects/python/{variant}/app.py')
  m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m)
  with tempfile.TemporaryDirectory() as d:
   m.DB=str(Path(d)/'lab.db');m.init_db()
   server=make_server('127.0.0.1',0,m.app);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
   base=f'http://127.0.0.1:{server.server_port}';v=variant=='vulnmart';part=2 if v else 5
   try:
    c=client();bad=http(c,base+'/login',{'username':'admin','password':'wrong'})
    record(part,variant+'-login-negative', 'Invalid credentials' in bad['body'],bad)
    normal=http(c,base+'/login',{'username':'sarah','password':'sarah1995'})
    own=http(c,base+'/order/2');other=http(c,base+'/order/1')
    record(part,variant+'-own-order',own['status']==200 and '1881' in own['body'],own)
    record(part,variant+'-idor',other['status']==(200 if v else 404) and (('4242' in other['body'])==v),other)
    c=client();inj=http(c,base+'/login',{'username':"admin' --",'password':'wrong'})
    order=http(c,base+'/order/1')
    record(part,variant+'-sqli',('4242' in order['body'])==v,{'login':inj,'order':order,'payload':"admin' --"})
    c=client();payload='<script>window.RBPO_XSS=1</script>'
    http(c,base+'/product/1/review',{'comment':payload})
    page=http(client(),base+'/product/1')
    record(part,variant+'-stored-xss', (payload in page['body'])==v and (v or '&lt;script&gt;' in page['body']),
       {'response':page,'payload':payload,'scope':'HTTP HTML output; browser JS execution not tested'})
   finally:server.shutdown();thread.join();server.server_close()
