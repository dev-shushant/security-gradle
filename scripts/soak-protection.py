#!/usr/bin/env python3
"""Bounded foreground-idle resource sampling of the explored owned benchmark pair.
This is emulator resource evidence, not a battery, leak-freedom or scan-cadence certification.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--prepared', type=Path, required=True)
p.add_argument('--device', required=True)
p.add_argument('--output', type=Path, required=True)
p.add_argument('--seconds', type=int, default=120)
p.add_argument('--interval', type=int, default=10)
a = p.parse_args()
if not 30 <= a.seconds <= 600 or not 5 <= a.interval <= 30:
    p.error('Use a bounded 30–600 second duration and 5–30 second interval')
prepared = json.loads(a.prepared.read_text())
package = prepared['applicationId']
if not re.fullmatch(r'com[.]apparmorx[.]consumer[.]benchmark[A-Za-z0-9_]*', package):
    p.error('Only owned benchmark fixtures are permitted')
a.output.mkdir(parents=True, exist_ok=True)
if any(a.output.iterdir()): p.error('Output must be empty')

def adb(*args):
    return subprocess.run(['adb','-s',a.device,*args], text=True, capture_output=True, timeout=30)

def checked(*args):
    result=adb(*args)
    if result.returncode: raise RuntimeError(result.stdout+result.stderr)
    return result.stdout.strip()

def foreground():
    state=checked('shell','dumpsys','activity','activities')
    return any('topResumedActivity=' in line and package+'/com.apparmorx.consumer.MainActivity' in line for line in state.splitlines())

result={'status':'incomplete','scope':'Foreground idle; matched source dependency graph; OBSERVE protection fixture; single emulator.',
        'secondsPerMode':a.seconds,'intervalSeconds':a.interval,'modeOrder':['baseline','protected'],
        'initialWarmupSeconds':10,'performanceBudgetEstablished':False,'batteryQualified':False,'scanCadenceQualified':False,
        'limits':['Single fixed-order run; host/OS/compilation state not fully controlled.',
                  'PSS snapshots are not peak-allocation or leak-freedom proof.',
                  'Process CPU ticks are cumulative; denied readings remain unavailable.',
                  'No physical, default blocking-profile or application workload qualification.'],
        'hostLoadAverageStart':os.getloadavg(),'prepared':prepared,'samples':[]}

def save(): (a.output/'summary.json').write_text(json.dumps(result,indent=2)+'\n')

try:
    assert checked('shell','getprop','sys.boot_completed')=='1'
    result['avd']=checked('emu','avd','name').splitlines()[0]
    hz=checked('shell','getconf','CLK_TCK');result['clockTicksPerSecond']=int(hz) if hz.isdigit() else None
    for mode in result['modeOrder']:
        artifact=prepared['artifacts'][mode];apk=Path(artifact['path'])
        assert hashlib.sha256(apk.read_bytes()).hexdigest()==artifact['sha256']
        checked('shell','am','force-stop',package)
        assert 'Success' in checked('install','-r',str(apk))
        installed=checked('shell','pm','path',package).splitlines()[0].removeprefix('package:')
        assert checked('shell','sha256sum',installed).split()[0]==artifact['sha256']
        launch=checked('shell','am','start','-S','-W','-n',package+'/com.apparmorx.consumer.MainActivity')
        (a.output/(mode+'-launch.log')).write_text(launch)
        assert 'Status: ok' in launch and foreground()
        pid=checked('shell','pidof',package);assert pid.isdigit()
        started=time.monotonic()
        for index in range(a.seconds//a.interval+1):
            target=started+index*a.interval
            time.sleep(max(0,target-time.monotonic()))
            assert checked('shell','pidof',package)==pid and foreground(), 'Owned process/window did not remain alive'
            stat=adb('shell','cat','/proc/'+pid+'/stat');ticks=None
            if stat.returncode==0 and ')' in stat.stdout:
                fields=stat.stdout.rsplit(')',1)[1].split()
                ticks=int(fields[11])+int(fields[12])
            (a.output/f'{mode}-{index}-stat.log').write_text(stat.stdout+stat.stderr)
            memory=checked('shell','dumpsys','meminfo',package)
            (a.output/f'{mode}-{index}-memory.log').write_text(memory)
            match=re.search(r'TOTAL PSS:\s*([\d,]+)',memory);assert match, 'PSS unavailable'
            row={'mode':mode,'pid':int(pid),'elapsedSeconds':round(time.monotonic()-started,3),
                 'excludedInitialWarmup':index*a.interval<10,'pssKiB':int(match.group(1).replace(',','')),'cpuTicks':ticks}
            result['samples'].append(row);save()
        print('Sampled foreground idle:',mode,flush=True)
    result['hostLoadAverageEnd']=os.getloadavg();result['status']='measurement-complete';save()
except Exception as error:
    result['status']='failed';result['failure']=str(error);save();raise
finally:
    adb('shell','am','force-stop',package)
