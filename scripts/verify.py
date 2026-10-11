#!/usr/bin/env python3
from common import *
from check_python import python_checks
from check_cpp import cpp_checks
from check_js import js_checks
from scan import sast

def main():
 parser=argparse.ArgumentParser();parser.add_argument('--only',choices=['python','cpp','js','sast','all'],default='all');args=parser.parse_args()
 errors=[]
 for key,fn in [('python',python_checks),('cpp',cpp_checks),('js',js_checks),('sast',sast)]:
  if args.only not in [key,'all']:continue
  try:fn()
  except Exception as exc:errors.append({'phase':key,'error':repr(exc)});print('ERROR',key,repr(exc),flush=True)
 summary={'timestamp_utc':datetime.now(timezone.utc).isoformat(),'platform':platform.platform(),'python':sys.version,'scope':args.only,'tests':records,'errors':errors,'passed':sum(x['passed'] for x in records),'total':len(records)}
 save(5,'verification-'+args.only+'.json',summary)
 return 1 if errors or any(not x['passed'] for x in records) else 0

if __name__ == "__main__": raise SystemExit(main())
