#!/usr/bin/env python3
"""Real local verification. Each result retains command/response and assertion."""
import argparse, contextlib, http.cookiejar as cookiejar, importlib.util, json, os, platform
from pathlib import Path
import shutil, subprocess, sys, tempfile, threading, time, urllib.request, urllib.parse, urllib.error
from datetime import datetime, timezone
R=Path(__file__).resolve().parents[1]
records=[]
def save(part,name,value):
 p=R/f'reports/participant-{part:02d}/evidence'/name;p.parent.mkdir(parents=True,exist_ok=True)
 p.write_text(value if isinstance(value,str) else json.dumps(value,ensure_ascii=False,indent=2)+'\n')

def record(part,name,ok,detail):
 item={'test':name,'passed':bool(ok),'details':detail};records.append(item);save(part,name+'.json',item)
 print(('PASS ' if ok else 'FAIL ')+name,flush=True)

def command(args,timeout=60,cwd=R,env=None):
 p=subprocess.run([str(x) for x in args],capture_output=True,text=True,cwd=cwd,timeout=timeout,env=env)
 return {'command':[str(x) for x in args],'returncode':p.returncode,'stdout':p.stdout,'stderr':p.stderr}

def client():return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookiejar.CookieJar()))

def http(c,url,data=None):
 req=urllib.request.Request(url,data=urllib.parse.urlencode(data).encode() if data is not None else None)
 try:resp=c.open(req,timeout=8)
 except urllib.error.HTTPError as exc:resp=exc
 with resp:return {'url':resp.url,'status':resp.code,'body':resp.read().decode('utf-8','replace')}
