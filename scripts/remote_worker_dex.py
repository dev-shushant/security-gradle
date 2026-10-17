"""Static remote-worker checks against actual mapped final DEX, without worker keep rules."""
import re


def verify_remote_worker_dex(disassembly, mapping):
    def methods(original):
        match = re.search(r'^' + re.escape(original) + r' -> ([^:]+):$', mapping, re.MULTILINE)
        if not match:
            return []
        descriptor = 'L' + match.group(1).replace('.', '/') + ';'
        return [method for block in disassembly.split('Class #')
                if "Class descriptor  : '" + descriptor + "'" in block
                for method in re.split(r'(?m)^\s*#\d+\s+:\s+\(in ', block)]

    remote = methods('androidx.work.multiprocess.RemoteCoroutineWorker')
    remote += methods('com.apparmorx.consumer.ConsumerRemoteWorker')
    tracked = [m for m in remote if re.search(r'invoke-static[^\n]*RemoteWorkerCancellation;\.track:', m)]
    if not tracked or not all(re.search(r'invoke-static[^\n]*SecurityGuard;\.allowWorker', m) and
            m.index('SecurityGuard') < m.index('RemoteWorkerCancellation') and 'SecurityException' in m for m in tracked):
        raise ValueError('remote returned-Future tracking/entry denial missing')

    cleanup = [m for m in methods('com.apparmorx.consumer.ConsumerRemoteWorker') +
               methods('com.apparmorx.consumer.ConsumerRemoteWorker$doRemoteWork$1')
               if 'AppArmorX ordinary R8 remote cleanup' in m]
    if not cleanup or any(re.search(r'invoke-static[^\n]*SecurityGuard;\.allowWorker', m) for m in cleanup):
        raise ValueError('remote suspend cleanup removed or guarded')

    stops = [m for m in methods('androidx.work.ListenableWorker')
             if re.search(r'invoke-static[^\n]*RemoteWorkerCancellation;\.stopped:', m)]
    def stop_paths(method):
        # R8 may put move-exception before normal cleanup and jump over it. Text order
        # cannot establish the exception path; follow the actual DEX branch offsets.
        instructions = {int(offset, 16): code.split(' // ', 1)[0].strip()
                        for offset, code in re.findall(r'\|([0-9a-f]+): ([^\n]+)', method)}
        offsets = sorted(instructions)
        following = dict(zip(offsets, offsets[1:]))
        handlers = [int(target, 16) for target in re.findall(r'<any> -> 0x([0-9a-f]+)', method)]
        if not offsets or not handlers:
            return False

        def path_has_cleanup(start, exceptional):
            pending = [(start, False)]
            visited = set()
            terminals = 0
            while pending:
                offset, cancelled = pending.pop()
                if (offset, cancelled) in visited:
                    continue
                visited.add((offset, cancelled))
                code = instructions.get(offset)
                if code is None:
                    return False
                cancelled = cancelled or bool(re.search(r'invoke-static.*RemoteWorkerCancellation;\.stopped:', code))
                if code.startswith('return') or code.startswith('throw '):
                    if not cancelled or (exceptional and not code.startswith('throw ')):
                        return False
                    terminals += 1
                    continue
                if code.startswith('goto'):
                    target = re.search(r'goto(?:/\d+)? ([0-9a-f]+)', code)
                    if not target:
                        return False
                    successors = [int(target.group(1), 16)]
                elif code.startswith('if-'):
                    target = re.search(r', ([0-9a-f]+)$', code)
                    if not target or offset not in following:
                        return False
                    successors = [int(target.group(1), 16), following[offset]]
                else:
                    if 'switch' in code or offset not in following:
                        return False
                    successors = [following[offset]]
                pending.extend((successor, cancelled) for successor in successors)
            return terminals > 0

        return path_has_cleanup(offsets[0], False) and all(path_has_cleanup(h, True) for h in handlers)
    if not stops or not any(stop_paths(m) for m in stops):
        raise ValueError('framework stop compatibility normal/exception path missing')
    return {'guardedTrackedMethods': len(tracked), 'cleanupMethods': len(cleanup), 'stopMethods': len(stops)}


def verify_mutation_controls(disassembly, mapping):
    """The checker must reject independently removed mechanisms from this real artifact's dump."""
    mutations = {
        'missing-tracking': ('RemoteWorkerCancellation;.track:', 'RemoteWorkerCancellation;.removedTrack:'),
        'missing-entry-guard': ('SecurityGuard;.allowWorker', 'SecurityGuard;.removedAllowWorker'),
        'missing-cleanup': ('AppArmorX ordinary R8 remote cleanup', 'AppArmorX removed cleanup'),
        'missing-stop-bridge': ('RemoteWorkerCancellation;.stopped:', 'RemoteWorkerCancellation;.removedStop:'),
    }
    rejected = []
    for name, (before, after) in mutations.items():
        if before not in disassembly:
            raise ValueError('Mutation has no target: ' + name)
        try:
            verify_remote_worker_dex(disassembly.replace(before, after), mapping)
        except ValueError:
            rejected.append(name)
        else:
            raise ValueError('Checker accepted mutation: ' + name)
    # Independently remove each normal/exception call site from the real base-stop method.
    mapped = re.search(r'^androidx\.work\.ListenableWorker -> ([^:]+):$', mapping, re.MULTILINE)
    if not mapped:
        raise ValueError('Missing base worker mapping for stop-path controls')
    descriptor = 'L' + mapped.group(1).replace('.', '/') + ';'
    blocks = [b for b in disassembly.split('Class #') if "Class descriptor  : '" + descriptor + "'" in b]
    candidates = [m for b in blocks for m in re.split(r'(?m)^\s*#\d+\s+:\s+\(in ', b)
                  if 'move-exception' in m and 'RemoteWorkerCancellation;.stopped:' in m]
    if len(candidates) != 1:
        raise ValueError('Expected one mapped framework stop body for controls')
    method = candidates[0]
    calls = list(re.finditer(r'invoke-static[^\n]*RemoteWorkerCancellation;\.stopped:', method))
    if len(calls) != 2:
        raise ValueError('Expected distinct normal/exception stop calls for controls')
    for name, call in zip(['missing-normal-stop', 'missing-exception-stop'], calls):
        changed = method[:call.start()] + method[call.start():call.end()].replace('.stopped:', '.removedStop:') + method[call.end():]
        try:
            verify_remote_worker_dex(disassembly.replace(method, changed, 1), mapping)
        except ValueError:
            rejected.append(name)
        else:
            raise ValueError('Checker accepted mutation: ' + name)
    return rejected
