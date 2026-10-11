from common import *

def cpp_checks():
 build=R/'build';build.mkdir(exist_ok=True)
 for source,output,flags in [('vulnerable.cpp','original',[]),('harness.cpp','harness',['-fsanitize=address,undefined','-fno-omit-frame-pointer','-no-pie']),('fixed.cpp','fixed',['-fsanitize=address,undefined','-fno-omit-frame-pointer','-no-pie'])]:
  result=command(['g++','-std=c++17','-Wall','-Wextra','-Wformat=2','-g',*flags,R/'projects/cpp'/source,'-o',build/output])
  save(3 if output!='fixed' else 5,output+'-compile.json',result)
  if result['returncode']:raise RuntimeError('C++ compilation failed')
 for binary in ['harness','fixed']:
  v=binary=='harness';part=3 if v else 5
  for mode,payload in [('copy','test'),('copy','A'*64),('format','%%'),('command','x;printf RBPO_CMD')]:
   env=os.environ.copy();env['ASAN_OPTIONS']='detect_leaks=0'
   result=command([build/binary,mode,payload],env=env);result['ASAN_OPTIONS']='detect_leaks=0';key='cpp-'+binary+'-'+mode+('-long' if len(payload)>40 else '-short')
   if mode=='copy' and len(payload)>40:ok=(result['returncode']!=0 and 'stack-buffer-overflow' in result['stderr']) if v else result['returncode']==0 and payload in result['stdout']
   elif mode=='format':ok=result['returncode']==0 and result['stdout']==('%' if v else '%%')
   elif mode=='command':ok=result['returncode']==0 and result['stdout']==('x\nRBPO_CMD' if v else payload+'\n')
   else:ok=result['returncode']==0 and 'test' in result['stdout']
   record(part,key,ok,result)
