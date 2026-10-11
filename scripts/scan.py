from common import *

def sast():
 for variant in ['vulnmart','fixed']:
  result=command([sys.executable,'-m','bandit','-r',f'projects/python/{variant}','-f','json'])
  part=1 if variant=='vulnmart' else 5
  save(part,'bandit-'+variant+'.json',result['stdout']);save(part,'bandit-'+variant+'-execution.json',result)
  if result['returncode'] not in [0,1]:raise RuntimeError('Bandit failed')
 tool=os.environ.get('CPPCHECK','cppcheck')
 for source in ['vulnerable.cpp','fixed.cpp']:
  result=command([tool,'--enable=all','--inconclusive','--std=c++17','--library=std','--xml','--xml-version=2',f'projects/cpp/{source}'])
  part=3 if source=='vulnerable.cpp' else 5
  save(part,'cppcheck-'+source+'.xml',result['stderr']);save(part,'cppcheck-'+source+'-execution.json',result)
  if result['returncode']!=0:raise RuntimeError('Cppcheck failed')
 result=command(['node','node_modules/eslint/bin/eslint.js','vulnerable.js','fixed.js','-f','json'],cwd=R/'projects/javascript')
 save(4,'eslint.json',result['stdout']);save(4,'eslint-execution.json',result)
 if result['returncode'] not in [0,1]:raise RuntimeError('ESLint failed')
