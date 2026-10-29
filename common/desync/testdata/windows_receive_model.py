#!/usr/bin/env python3
"""Generate, never execute, a reversible Windows backend offline overlay.
Usage: windows_receive_model.py WORKTREE OUTPUT [EXACT_TREE]
Pass -tags=desync_windows_model to Go; this is not a Windows/native result.
"""
import hashlib,json,pathlib,subprocess,sys
W=pathlib.Path(sys.argv[1]).resolve();O=pathlib.Path(sys.argv[2]).resolve();O.mkdir(parents=True,exist_ok=False)
base=sys.argv[3] if len(sys.argv)>3 else None
replace={};provenance=[]
def source(p):
 return subprocess.check_output(['git','-C',str(W),'show',base+':'+p]) if base else (W/p).read_bytes()
def sha(b):return hashlib.sha256(b).hexdigest()
p='common/desync/backend_windows.go';original=source(p);text=original.decode()
marker='// prepareSocket establishes the owned endpoint';prefix,suffix=text.split(marker,1)
transforms=[('//go:build windows\n',''),('\t"net"\n',''),('\t"golang.org/x/sys/windows"\n',''),('func NewNativeBackend()','func NewWindowsReplayBackend()')]
for old,new in transforms:
 assert prefix.count(old)==1,(old,prefix.count(old));prefix=prefix.replace(old,new,1)
# Inverse at fixed anchors, including original unchanged suffix.
inverse=prefix.replace('func NewWindowsReplayBackend()','func NewNativeBackend()',1)
inverse='//go:build windows\n'+inverse
inverse=inverse.replace('\t"fmt"\n','\t"fmt"\n\t"net"\n',1)
inverse=inverse.replace('E "github.com/sagernet/sing/common/exceptions"\n','E "github.com/sagernet/sing/common/exceptions"\n\t"golang.org/x/sys/windows"\n',1)
assert (inverse+marker+suffix).encode()==original
out=O/'backend_replay.go';out.write_text(prefix);replace[str(W/'common/desync/backend_receive_replay.go')]=str(out)
provenance.append(dict(path=p,source_sha256=sha(original),replay_sha256=sha(out.read_bytes()),inverse_equal=True,transforms=transforms,suffix_sha256=sha((marker+suffix).encode())))
if base:
 for p in ['common/desync/engine.go','common/desync/endpoint_producer.go','protocol/direct/desync.go']:
  out=O/(p.replace('/','_'));data=source(p);out.write_bytes(data);replace[str(W/p)]=str(out)
  provenance.append(dict(path=p,source_sha256=sha(data),byte_identical=True))
for origin,target in [('windows_receive_boundary.go.txt','common/windivert/receive_model_boundary.go'),('windows_receive_support.go.txt','common/desync/receive_model_support.go')]:
 p=W/'common/desync/testdata'/origin;out=O/origin.removesuffix('.txt');out.write_bytes(p.read_bytes());replace[str(W/target)]=str(out)
 provenance.append(dict(path=str(p.relative_to(W)),sha256=sha(p.read_bytes()),model_only=True))
for name in ['backend_windows_retirement_test.go','backend_windows_send_retirement_test.go','capture_retained_open_windows_test.go']:
 p=W/'common/desync'/name;out=O/name.replace('_windows','_replay');out.write_text(p.read_text().replace('//go:build windows\n','',1));replace[str(W/'common/desync'/out.name)]=str(out)
(O/'overlay.json').write_text(json.dumps({'Replace':replace},indent=2)+'\n')
(O/'provenance.json').write_text(json.dumps(dict(exact_baseline=base,files=provenance),indent=2)+'\n')
print(O/'overlay.json')
