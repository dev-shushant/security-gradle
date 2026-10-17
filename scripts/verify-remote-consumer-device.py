#!/usr/bin/env python3
"""Replay the explored ordinary-R8 OBSERVE consumer UI; no SDK calls or test keep rules."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import time
import xml.etree.ElementTree as ET

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--device', required=True)
parser.add_argument('--apk', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
args = parser.parse_args()
args.output.mkdir(parents=True, exist_ok=True)
if any(args.output.iterdir()): parser.error('Output must be empty')
package = 'com.apparmorx.consumer.remotelifecycle'
adb = ['adb', '-s', args.device]

def run(*values):
    return subprocess.check_output(adb + list(values), text=True, stderr=subprocess.STDOUT, timeout=30).strip()

def hierarchy():
    run('shell', 'uiautomator', 'dump', '/sdcard/apparmorx-remote-window.xml')
    xml = run('shell', 'cat', '/sdcard/apparmorx-remote-window.xml')
    root = ET.fromstring(xml)
    if not any(n.get('package') == package for n in root.iter('node')):
        raise RuntimeError('Owned consumer UI is not foreground')
    return root, xml

def tap(label):
    root, _ = hierarchy()
    candidates = [n for n in root.iter('node') if n.get('content-desc') == label and n.get('enabled') == 'true']
    # Dynamic-only selector: coordinates come from this device's current bounds, never a guessed point.
    if len(candidates) != 1: raise RuntimeError('Missing unique control: ' + label)
    x1, y1, x2, y2 = map(int, re.findall(r'\d+', candidates[0].get('bounds')))
    run('shell', 'input', 'tap', str((x1+x2)//2), str((y1+y2)//2))

def wait_status(prefix):
    deadline = time.monotonic()+30
    while True:
        root, xml = hierarchy()
        for node in root.iter('node'):
            value = node.get('text', '')
            if value.startswith(prefix+' id='):
                return value, xml
        if time.monotonic() >= deadline: raise RuntimeError('Timed out waiting for '+prefix)
        time.sleep(.1)

def logs():
    return run('logcat', '-d', 'AAXRemoteConsumer:I', '*:S')

def counts(text, request):
    entered = re.findall(r'entered id='+request+r' pid=(\d+) uid=(\d+) wait=(true|false)', text)
    cleanup = re.findall(r'cleanup id='+request+r' pid=(\d+)', text)
    main = re.findall(r'enqueued id='+request+r' mainPid=(\d+) wait=(true|false)', text)
    return entered, cleanup, main

result = {'status':'incomplete', 'observeOnly':True, 'syntheticPosture':False, 'tests':[]}
try:
    result['avd'] = run('emu', 'avd', 'name').splitlines()[0].strip()
    result['shellIdentity'] = run('shell', 'id')
    result['apkSha256'] = hashlib.sha256(args.apk.read_bytes()).hexdigest()
    assert 'Success' in run('install', '-r', str(args.apk))
    installed = run('shell','pm','path',package).splitlines()[0].removeprefix('package:')
    assert run('shell','sha256sum',installed).split()[0] == result['apkSha256']
    package_dump = run('shell','dumpsys','package',package)
    (args.output/'package.txt').write_text(package_dump)
    assert 'DEBUGGABLE' not in package_dump
    uid_output = run('shell','cmd','package','list','packages','-U',package)
    package_uids = re.findall(r'^package:'+re.escape(package)+r' uid:(\d+)$', uid_output, re.MULTILINE)
    assert len(package_uids) == 1, 'Missing unique package UID'
    package_uid = int(package_uids[0])
    result['debuggable'] = False
    result['packageUid'] = package_uid
    run('shell','am','force-stop',package)
    run('shell','am','start','-W','-n',package+'/com.apparmorx.consumer.MainActivity')
    tap('Run remote worker')
    normal, xml = wait_status('SUCCEEDED')
    (args.output/'normal.xml').write_text(xml)
    request = re.search(r'id=([a-f0-9-]{36})',normal).group(1)
    e, c, m = counts(logs(), request)
    assert len(e)==len(c)==len(m)==1 and e[0][2]=='false'
    assert e[0][0]==c[0] and e[0][0]!=m[0][0] and int(e[0][1])==package_uid and package_uid>=10000
    assert 'remotePid='+e[0][0] in normal and 'remoteUid='+e[0][1] in normal and 'marker=AppArmorX remote output' in normal
    result['tests'].append({'case':'normal','passed':True,'id':request,'remotePid':int(e[0][0]),'mainPid':int(m[0][0]),'uid':int(e[0][1])})
    tap('Start pending worker')
    pending, _ = wait_status('RUNNING')
    request = re.search(r'id=([a-f0-9-]{36})',pending).group(1)
    deadline = time.monotonic()+30
    while True:
        e,c,m=counts(logs(),request)
        if e: break
        if time.monotonic()>=deadline: raise RuntimeError('Remote pending body never entered')
        time.sleep(.1)
    assert len(e)==len(m)==1 and not c and e[0][2]=='true' and e[0][0]!=m[0][0]
    assert run('shell','pidof',package+':worker') == e[0][0]
    deadline = time.monotonic()+30
    while ('awaiting id='+request+' pid='+e[0][0]) not in logs():
        if time.monotonic()>=deadline: raise RuntimeError('Remote GC/suspension checkpoint did not complete')
        time.sleep(.1)
    time.sleep(10) # Deliberately retain real pending work before its public cancellation.
    checkpoint, _ = wait_status('RUNNING')
    assert request in checkpoint and not counts(logs(), request)[1]
    tap('Cancel pending worker')
    cancelled, xml=wait_status('CANCELLED')
    assert request in cancelled
    deadline=time.monotonic()+30
    while True:
        raw=logs();entered,cleanup,main=counts(raw,request)
        if cleanup: break
        if time.monotonic()>=deadline: raise RuntimeError('CANCELLED remote work did not execute finally in the ordinary-R8 consumer')
        time.sleep(.2)
    tap('Cancel pending worker')
    entered,cleanup,main=counts(logs(),request)
    assert len(entered)==len(cleanup)==len(main)==1 and entered[0][0]==cleanup[0] and int(entered[0][1])==package_uid and package_uid>=10000
    (args.output/'cancelled.xml').write_text(xml)
    result['tests'].append({'case':'pending-cancellation','passed':True,'id':request,'remotePid':int(entered[0][0]),'mainPid':int(main[0][0]),'uid':int(entered[0][1]),'cleanupOnce':True,'pendingHoldSeconds':10})
    result['status']='passed'
except Exception as error:
    result['status']='failed';result['failure']=str(error)
    raise
finally:
    (args.output/'consumer.log').write_text(logs())
    (args.output/'summary.json').write_text(json.dumps(result,indent=2)+'\n')
    run('shell','am','force-stop',package)
