#!/usr/bin/env python3
"""Exercise compiled AppArmorX archive checks on real APK/AAB ZIP mutations.
No installation/signing occurs. Rewritten copies are unsigned and only test structural checks.
Build current plugin/runtime classes before invoking this host-only verifier.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import warnings
import zipfile

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--apk',type=Path,required=True)
parser.add_argument('--aab',type=Path,required=True)
parser.add_argument('--output',type=Path,required=True)
parser.add_argument('--kotlin-stdlib',type=Path)
args=parser.parse_args()
root=Path(__file__).resolve().parents[1]
if any(not p.is_file() for p in [args.apk,args.aab]):parser.error('Both source artifacts must exist')
args.output.mkdir(parents=True,exist_ok=True)
if any(args.output.iterdir()):parser.error('Output must be empty')
stdlib=args.kotlin_stdlib
if stdlib is None:
    candidates=list((Path.home()/'.gradle/caches/modules-2/files-2.1/org.jetbrains.kotlin/kotlin-stdlib/2.2.21').glob('*/kotlin-stdlib-2.2.21.jar'))
    if len(candidates)!=1:parser.error('Supply --kotlin-stdlib explicitly')
    stdlib=candidates[0]
runtime=root/'runtime/build/intermediates/compile_library_classes_jar/debug/bundleLibCompileToJarDebug/classes.jar'
plugin=root/'plugin/build/classes/kotlin/main'
if not runtime.is_file() or not plugin.is_dir():parser.error('Build current plugin and runtime classes first')

PROBE='import java.io.File;\nimport java.util.Collections;\npublic class ArchiveProbe {\n public static void main(String[] paths) throws Exception {\n  Class<?> runtime=Class.forName("com.apparmorx.runtime.ApkIntegrityVerifier");\n  Object instance=runtime.getField("INSTANCE").get(null);\n  java.lang.reflect.Method verify=runtime.getMethod("verify",File.class,java.util.Map.class);\n  Class<?> plugin=Class.forName("com.apparmorx.gradle.ProtectionArchiveKt");\n  for(String path:paths) {\n   File file=new File(path);boolean bundle=path.endsWith(".aab");\n   java.lang.reflect.Method audit=plugin.getMethod(bundle?"auditBundleProtectionArchive":"auditProtectionArchive",File.class);\n   java.util.List<?> failures=(java.util.List<?>)audit.invoke(null,file);\n   String accepted=bundle?"NA":verify.invoke(instance,file,Collections.emptyMap()).toString();\n   System.out.println(file.getName()+"|"+accepted+"|"+failures);\n  }\n }\n}\n'

(args.output/'ArchiveProbe.java').write_text(PROBE)
paths=[];expected={}
for kind,archive in [('apk',args.apk),('aab',args.aab)]:
    primary='classes.dex' if kind=='apk' else 'base/dex/classes.dex'
    policy='assets/apparmorx/policy.properties' if kind=='apk' else 'base/assets/apparmorx/policy.properties'
    native='lib/arm64-v8a/libapparmorx.so' if kind=='apk' else 'base/lib/arm64-v8a/libapparmorx.so'
    for mutation,target in [('original',None),('duplicate-policy',policy),('duplicate-dex',primary),('duplicate-native',native),('secondary-only',primary),('repeated-directory',None)]:
        path=args.output/(mutation+'.'+kind)
        if mutation=='original':path.write_bytes(archive.read_bytes())
        else:
            with zipfile.ZipFile(archive) as source,zipfile.ZipFile(path,'w') as dest:
                for entry in source.infolist():
                    name=entry.filename
                    if mutation=='secondary-only' and name==primary:name=name.replace('classes.dex','classes2.dex')
                    dest.writestr(name,source.read(entry),compress_type=entry.compress_type)
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore',UserWarning)
                    if mutation.startswith('duplicate-'):dest.writestr(target,source.read(target))
                    if mutation=='repeated-directory':
                        directory='assets/control/' if kind=='apk' else 'base/assets/control/'
                        dest.writestr(directory,b'');dest.writestr(directory,b'')
        paths.append(path);expected[path.name]=mutation in ['original','repeated-directory']
cp=os.pathsep.join(map(str,[plugin,runtime,stdlib]))
raw=subprocess.check_output(['java','-cp',cp,str(args.output/'ArchiveProbe.java'),*map(str,paths)],text=True,stderr=subprocess.STDOUT,timeout=120)
(args.output/'probe.log').write_text(raw)
results=[]
for line in raw.splitlines():
    name,accepted,failures=line.split('|',2);valid=expected[name]
    assert (failures=='[]')==valid,(name,failures)
    if accepted!='NA':assert (accepted=='true')==valid,(name,accepted)
    results.append({'archive':name,'runtimeStructuralAccepted':None if accepted=='NA' else accepted=='true','buildAuditAccepted':failures=='[]','expectedAccepted':valid,'auditFailures':failures,'sha256':hashlib.sha256((args.output/name).read_bytes()).hexdigest()})
assert len(results)==12
summary={'status':'host-archive-checks-passed','results':results,'runtimeClassesSha256':hashlib.sha256(runtime.read_bytes()).hexdigest(),
         'limits':['Unsigned mutations were not installed.','Structural archive checks only; not signer authentication or device response.']}
(args.output/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
print('PASS: 12 host archive cases; no device/signing claim')
