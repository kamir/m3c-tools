package dependencies

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const pythonFixture = `
import importlib.metadata as metadata, json, os, pathlib, shutil, sys, venv
import packaging
base=pathlib.Path(sys.argv[1])
venv.EnvBuilder(with_pip=False,symlinks=(os.name != 'nt')).create(base)
exe=base/('Scripts/python.exe' if os.name=='nt' else 'bin/python')
site=base/('Lib/site-packages' if os.name=='nt' else ('lib/python%d.%d/site-packages'%sys.version_info[:2]))
site.mkdir(parents=True,exist_ok=True)
shutil.copytree(pathlib.Path(packaging.__file__).parent,site/'packaging',dirs_exist_ok=True)
dist=metadata.distribution('packaging')
shutil.copytree(dist._path,site/pathlib.Path(dist._path).name,dirs_exist_ok=True)
for name,version,requires in [('demo-a','1.2.3',['demo-b[feature]>=2','missing; sys_platform == "impossible"']),('demo-b','2.1',['demo-c>=3; extra == "feature"']),('demo-c','3.1',[])]:
 module=name.replace('-','_')+'.py'
 (site/module).write_text('raise RuntimeError("target distribution imported")\n')
 info=site/(name.replace('-','_')+'-'+version+'.dist-info');info.mkdir()
 (info/'METADATA').write_text('Metadata-Version: 2.3\nName: '+name+'\nVersion: '+version+'\nRequires-Python: >=3.8\nProvides-Extra: feature\n'+''.join('Requires-Dist: '+r+'\n' for r in requires))
 rel=info.name
 (info/'RECORD').write_text(module+',,\n'+rel+'/METADATA,,\n'+rel+'/RECORD,,\n')
print(json.dumps(dict(path=str(exe),site=str(site))))
`

func TestPythonRuntimeFixture(t *testing.T) {
	home := isolated(t)
	base := os.Getenv("M3C_DEPENDENCY_TEST_PYTHON")
	if base == "" {
		t.Skip("explicit fixture Python with venv and packaging not selected")
	}
	if !filepath.IsAbs(base) {
		t.Fatal("fixture Python must be absolute")
	}
	// This creates only a temporary synthetic environment. No installed target
	// distribution or developer credential is used as a successful fixture.
	setup, e := probe(context.Background(), Profile{ProjectRoot: home}, base, []string{"-I", "-B", "-c", pythonFixture, filepath.Join(home, "env")}, nil)
	if e != nil {
		t.Fatalf("synthetic fixture prerequisite unavailable: %v", e)
	}
	var fixture struct {
		Path string `json:"path"`
		Site string `json:"site"`
	}
	if strictJSON(setup, &fixture) != nil {
		t.Fatal("fixture protocol")
	}
	_, tree, e := siteFingerprint(context.Background(), fixture.Site)
	if e != nil {
		t.Fatal(e)
	}
	p := Profile{Schema: ProfileSchema, ProjectRoot: home, Python: &Python{Path: fixture.Path, SitePackages: fixture.Site, TreeDigest: tree}, Tools: []Tool{}}
	// Explicit fixture baseline approval is a test operation, not Resolve behavior.
	approve := func() *Resolver {
		t.Helper()
		_, h, e := siteFingerprint(context.Background(), fixture.Site)
		if e != nil {
			t.Fatal(e)
		}
		p.Python.TreeDigest = h
		if runtime.GOOS == "windows" {
			root, e := windowsVenvRoot(p.Python)
			if e != nil {
				t.Fatal(e)
			}
			_, rootHash, e := siteFingerprint(context.Background(), root)
			if e != nil {
				t.Fatal(e)
			}
			p.Python.InterpreterRootDigest = rootHash
		}
		r, e := NewResolver(p, nil)
		if e != nil {
			t.Fatal(e)
		}
		return r
	}
	r := approve()
	root := artifact("root", dep("python", "Demo_A", ">=1.2,<2"))
	out, e := r.Resolve(context.Background(), root)
	if e != nil {
		t.Fatal(e)
	}
	names := map[string]bool{}
	for _, o := range out.Runtime {
		names[o.Name] = true
	}
	for _, name := range []string{"demo-a", "demo-b", "demo-c", "packaging", "interpreter"} {
		if !names[name] {
			t.Fatalf("missing transitive observation %s", name)
		}
	}
	for attempt := 0; attempt < 3; attempt++ {
		if _, e := r.Recheck(context.Background(), root, out.LockDigest); e != nil {
			observed, diagnostic := r.Resolve(context.Background(), root)
			if diagnostic == nil {
				for i, before := range out.Runtime {
					if i >= len(observed.Runtime) || before != observed.Runtime[i] {
						t.Fatalf("recheck %d: %v; runtime observation %d changed (kind=%s name=%s)", attempt, e, i, before.Kind, before.Name)
					}
				}
			}
			t.Fatalf("recheck %d: %v; repeat resolution error=%v", attempt, e, diagnostic)
		}
	}
	if runtime.GOOS == "windows" {
		altered := p
		copyPython := *p.Python
		altered.Python = &copyPython
		altered.Python.InterpreterRootDigest = strings.Repeat("0", 64)
		denied, e := NewResolver(altered, nil)
		if e != nil {
			t.Fatal(e)
		}
		if out, e := denied.Resolve(context.Background(), root); !errors.Is(e, ErrDrift) || out != nil {
			t.Fatal("Windows root baseline silently learned")
		}
		venvRoot, e := windowsVenvRoot(p.Python)
		if e != nil {
			t.Fatal(e)
		}
		cfg := filepath.Join(venvRoot, "pyvenv.cfg")
		body, e := os.ReadFile(cfg)
		if e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(cfg, append(append([]byte{}, body...), []byte("\n# synthetic changed config\n")...), 0600); e != nil {
			t.Fatal(e)
		}
		if _, e := r.Recheck(context.Background(), root, out.LockDigest); !errors.Is(e, ErrDrift) {
			t.Fatal("Windows interpreter root change not bound")
		}
		if e := os.WriteFile(cfg, body, 0600); e != nil {
			t.Fatal(e)
		}
	}

	for _, constraint := range []string{">=9", "^1", "https://synthetic.invalid/pkg"} {
		root.Declarations[0].Constraint = constraint
		if _, e := r.Resolve(context.Background(), root); !errors.Is(e, ErrUnresolved) {
			t.Fatalf("constraint not denied: %v", e)
		}
	}
	root.Declarations[0].Constraint = ">=1"
	module := filepath.Join(fixture.Site, "demo_c.py")
	if e := os.WriteFile(module, []byte("raise RuntimeError('different synthetic code')\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := r.Recheck(context.Background(), root, out.LockDigest); !errors.Is(e, ErrDrift) {
		t.Fatalf("file tamper: %v", e)
	}
	metadataPath := filepath.Join(fixture.Site, "demo_b-2.1.dist-info", "METADATA")
	b, e := os.ReadFile(metadataPath)
	if e != nil {
		t.Fatal(e)
	}
	original := string(b)
	for _, metadata := range []string{strings.Replace(original, "demo-c>=3; extra == \"feature\"", "missing>=3", 1), strings.Replace(original, "demo-c>=3; extra == \"feature\"", "demo-c @ https://synthetic.invalid/pkg", 1), strings.Replace(original, ">=3.8", ">999", 1)} {
		if e := os.WriteFile(metadataPath, []byte(metadata), 0600); e != nil {
			t.Fatal(e)
		}
		if _, e := approve().Resolve(context.Background(), root); !errors.Is(e, ErrUnresolved) {
			t.Fatalf("transitive failure not denied: %v", e)
		}
	}
	if e := os.WriteFile(metadataPath, []byte(original), 0600); e != nil {
		t.Fatal(e)
	}
	missingPackaging := filepath.Join(fixture.Site, "packaging-unavailable")
	if e := os.Rename(filepath.Join(fixture.Site, "packaging"), missingPackaging); e != nil {
		t.Fatal(e)
	}
	if _, e := approve().Resolve(context.Background(), root); !errors.Is(e, ErrUnresolved) {
		t.Fatalf("missing explicit packaging prerequisite: %v", e)
	}

	if e := os.Rename(missingPackaging, filepath.Join(fixture.Site, "packaging")); e != nil {
		t.Fatal(e)
	}
	// A deliberately operator-approved sparse inventory must still be refused.
	recordPath := filepath.Join(fixture.Site, "demo_a-1.2.3.dist-info", "RECORD")
	record, e := os.ReadFile(recordPath)
	if e != nil {
		t.Fatal(e)
	}
	for _, sparse := range []string{"demo_a.py,,\ndemo_a-1.2.3.dist-info/RECORD,,\n", "demo_a-1.2.3.dist-info/RECORD,,\n", "demo_a-1.2.3.dist-info/METADATA,,\ndemo_a-1.2.3.dist-info/RECORD,,\n"} {
		if e := os.WriteFile(recordPath, []byte(sparse), 0600); e != nil {
			t.Fatal(e)
		}
		if out, e := approve().Resolve(context.Background(), root); e == nil || out != nil {
			t.Fatal("sparse inventory produced complete lock")
		}
	}
	if e := os.WriteFile(recordPath, record, 0600); e != nil {
		t.Fatal(e)
	}
	valid := approve()
	fresh, e := valid.Resolve(context.Background(), root)
	if e != nil {
		t.Fatal(e)
	}
	if e := os.Remove(filepath.Join(fixture.Site, "demo_a.py")); e != nil {
		t.Fatal(e)
	}
	if _, e := valid.Recheck(context.Background(), root, fresh.LockDigest); !errors.Is(e, ErrDrift) {
		t.Fatalf("module loss accepted: %v", e)
	}
	if e := os.WriteFile(filepath.Join(fixture.Site, "demo_a-1.2.3.dist-info", "METADATA"), []byte("Name: demo-a\nVersion: 1.2.3\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := valid.Recheck(context.Background(), root, fresh.LockDigest); !errors.Is(e, ErrDrift) {
		t.Fatalf("metadata mutation accepted: %v", e)
	}
	// A clean but unrelated operator-selected tree cannot stand in for active site.
	unrelated := t.TempDir()
	_, otherHash, e := siteFingerprint(context.Background(), unrelated)
	if e != nil {
		t.Fatal(e)
	}
	p.Python.SitePackages = unrelated
	p.Python.TreeDigest = otherHash
	other, e := NewResolver(p, nil)
	if runtime.GOOS == "windows" {
		if !errors.Is(e, ErrInvalid) {
			t.Fatal("unrelated site accepted by Windows profile")
		}
	} else if e != nil {
		t.Fatal(e)
	}
	if runtime.GOOS != "windows" {
		if out, e := other.Resolve(context.Background(), root); e == nil || out != nil {
			t.Fatal("unrelated clean tree accepted")
		}
	}

	// An additional active .pth root is outside the single-site profile contract.
	if e := os.WriteFile(filepath.Join(fixture.Site, "demo_a.py"), []byte("raise RuntimeError('synthetic target')\n"), 0600); e != nil {
		t.Fatal(e)
	}
	aMetadata := filepath.Join(fixture.Site, "demo_a-1.2.3.dist-info", "METADATA")
	if e := os.WriteFile(aMetadata, []byte("Name: demo-a\nVersion: 1.2.3\n"), 0600); e != nil {
		t.Fatal(e)
	}
	external := filepath.Join(home, "external-packages")
	if e := os.Mkdir(external, 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(fixture.Site, "external.pth"), []byte(external+"\n"), 0600); e != nil {
		t.Fatal(e)
	}
	p.Python.SitePackages = fixture.Site
	if out, e := approve().Resolve(context.Background(), root); e == nil || out != nil {
		t.Fatal("unmeasured .pth package root accepted")
	}
	if e := os.Remove(filepath.Join(fixture.Site, "external.pth")); e != nil {
		t.Fatal(e)
	}
	// A clean but wrong fingerprint is never silently enrolled or learned.
	p.Python.TreeDigest = strings.Repeat("0", 64)
	unapproved, e := NewResolver(p, nil)
	if e != nil {
		t.Fatal(e)
	}
	if out, e := unapproved.Resolve(context.Background(), root); !errors.Is(e, ErrDrift) || out != nil {
		t.Fatal("operator fingerprint silently learned")
	}

}

const windowsSiteFixture = `
import json,os,pathlib,site,sys,types
request=json.load(sys.stdin)
home=pathlib.Path(request['home'])/'windows-classification'
root=home/'env';base=home/'base';stdlib=base/'Lib';selected=root/'Lib'/'site-packages';extra=home/'foreign'
for path in (selected,root/'Scripts',stdlib,extra):path.mkdir(parents=True,exist_ok=True)
(root/'pyvenv.cfg').write_text('home = synthetic\n')
(root/'Scripts'/'python.exe').write_bytes(b'synthetic launcher')
namespace={'__name__':'classification_fixture'};exec(request['probe'],namespace)
# Exercise the installed CPython stdlib's actual Windows getsitepackages branch.
separator=os.sep
try:
 os.sep='\\'
 roots=site.getsitepackages([str(root)])
finally:os.sep=separator
assert {os.path.realpath(p) for p in roots}=={os.path.realpath(root),os.path.realpath(selected)}
namespace['os']=types.SimpleNamespace(name='nt',path=os.path)
namespace['sysconfig']=types.SimpleNamespace(get_path=lambda key:str(stdlib))
state=types.SimpleNamespace(prefix=str(root),base_prefix=str(base),executable=str(root/'Scripts'/'python.exe'),path=[str(root),str(selected),str(stdlib)],version_info=sys.version_info)
namespace['sys']=state
sites=types.SimpleNamespace(ENABLE_USER_SITE=False,getsitepackages=lambda:roots)
namespace['site']=sites
classify=namespace['_classify_sites']
assert classify(os.path.realpath(selected),str(root))==os.path.realpath(root)
checks=['actual-stdlib-windows-branch','normal-venv-prefix-bound']
def deny(label,selected_path,expected):
 try:classify(selected_path,expected)
 except ValueError:checks.append(label)
 else:raise AssertionError(label)
deny('missing-root',os.path.realpath(selected),'')
deny('foreign-root',os.path.realpath(selected),str(extra))
deny('wrong-selected-site',os.path.realpath(extra),str(root))
state.base_prefix=str(root);deny('global-python',os.path.realpath(selected),str(root));state.base_prefix=str(base)
state.executable=str(base/'python.exe');deny('wrong-launcher',os.path.realpath(selected),str(root));state.executable=str(root/'Scripts'/'python.exe')
(root/'pyvenv.cfg').unlink();deny('missing-venv-config',os.path.realpath(selected),str(root));(root/'pyvenv.cfg').write_text('home = synthetic\n')
roots.append(str(extra));deny('extra-active-site',os.path.realpath(selected),str(root));roots.pop()
state.path.append(str(extra));deny('extra-pth-root',os.path.realpath(selected),str(root));state.path.pop()
namespace['os']=types.SimpleNamespace(name='posix',path=os.path)
deny('windows-root-on-unix',os.path.realpath(selected),str(root))
print(json.dumps(checks))
`

func TestWindowsVenvSiteClassification(t *testing.T) {
	home := isolated(t)
	base := os.Getenv("M3C_DEPENDENCY_TEST_PYTHON")
	if base == "" {
		t.Skip("explicit fixture Python not selected")
	}
	input, e := json.Marshal(struct {
		Home  string `json:"home"`
		Probe string `json:"probe"`
	}{home, pythonProbe})
	if e != nil {
		t.Fatal(e)
	}
	out, e := probe(context.Background(), Profile{ProjectRoot: home}, base, []string{"-I", "-B", "-c", windowsSiteFixture}, input)
	if e != nil {
		t.Fatal(e)
	}
	var cases []string
	if strictJSON(out, &cases) != nil || len(cases) != 11 {
		t.Fatalf("Windows stdlib branch fixture failed: %s", out)
	}
	root := filepath.Join(home, "env")
	p := &Python{Path: filepath.Join(root, "Scripts", "python.exe"), SitePackages: filepath.Join(root, "Lib", "site-packages"), TreeDigest: strings.Repeat("a", 64), InterpreterRootDigest: strings.Repeat("b", 64)}
	if selected, e := windowsVenvRoot(p); e != nil || selected != root {
		t.Fatal("normal Windows path derivation failed")
	}
	p.Path = filepath.Join(root, "python.exe")
	if _, e := windowsVenvRoot(p); !errors.Is(e, ErrInvalid) {
		t.Fatal("global Windows Python path accepted")
	}
	p.Path = filepath.Join(root, "Scripts", "python.exe")
	profile := Profile{Schema: ProfileSchema, ProjectRoot: home, Python: p}
	if runtime.GOOS != "windows" {
		if _, e := NewResolver(profile, nil); !errors.Is(e, ErrInvalid) {
			t.Fatal("Windows root digest silently ignored on Unix")
		}
	} else {
		p.InterpreterRootDigest = ""
		if _, e := NewResolver(profile, nil); !errors.Is(e, ErrInvalid) {
			t.Fatal("Windows root baseline missing accepted")
		}
	}
	p.InterpreterRootDigest = strings.Repeat("b", 64)
	raw, e := json.Marshal(profile)
	if e != nil {
		t.Fatal(e)
	}
	alias := strings.Replace(string(raw), `"interpreter_root_digest"`, `"Interpreter_Root_Digest"`, 1)
	if _, e := ParseProfile([]byte(alias)); !errors.Is(e, ErrInvalid) {
		t.Fatal("Windows field alias accepted")
	}
	huge := profile
	largePython := *profile.Python
	largePython.InterpreterRootDigest = strings.Repeat("b", 65)
	huge.Python = &largePython
	if typedProfileBudget(huge) {
		t.Fatal("root digest bypassed typed size budget")
	}

}

const windowsMarkerFixture = `
import ctypes,io,json,os,pathlib,platform,sys,types
request=json.load(sys.stdin)
namespace={'__name__':'marker_fixture'};exec(request['probe'],namespace)
selected=request['site']
# Site classification is tested separately; simulate Windows marker collection
# against this real, temporary distribution inventory on every producer OS.
namespace['_classify_sites']=lambda site,root:''
class WindowsOS:
 name='nt'
 def __getattr__(self,key):return getattr(os,key)
namespace['os']=WindowsOS()
state={'native':0x8664,'process':0,'error':False,'write':True,'false':False,'missing':False}
class CurrentProcess:
 def __call__(self):
  assert self.argtypes==[] and self.restype is ctypes.c_void_p
  return 123
class MachineInfo:
 def __call__(self,process,process_machine,native_machine):
  assert process==123 and self.restype is ctypes.c_int32
  assert self.argtypes==[ctypes.c_void_p,ctypes.POINTER(ctypes.c_uint16),ctypes.POINTER(ctypes.c_uint16)]
  if state['error']:raise OSError('synthetic API unavailable')
  if state['write']:
   process_machine._obj.value=state['process'];native_machine._obj.value=state['native']
  return 0 if state['false'] else 1
class Kernel:
 GetCurrentProcess=CurrentProcess()
 @property
 def IsWow64Process2(self):
  if state['missing']:raise AttributeError('synthetic API absent')
  return MachineInfo()
def dll(name,**kwargs):
 assert name=='kernel32' and kwargs=={'use_last_error':True}
 return Kernel()
ctypes.WinDLL=dll
os.environ['PROCESSOR_ARCHITECTURE']='poisoned'
os.environ['PROCESSOR_ARCHITEW6432']='poisoned'
checks=[]
for code,want in [(0x014c,'x86'),(0x01c0,'ARM'),(0x01c4,'ARM'),(0x0200,'ia64'),(0x8664,'AMD64'),(0xaa64,'ARM64')]:
 state['native']=code
 assert namespace['_windows_machine']()==want
 checks.append('native-'+want)
for process,native,want in [(0x8664,0xaa64,'ARM64'),(0x014c,0x8664,'AMD64')]:
 state.update(process=process,native=native)
 assert namespace['_windows_machine']()==want
 checks.append('emulation-'+want)
for mode in ('unknown','unwritten','api-error','false','absent'):
 state.update(native=0 if mode=='unknown' else 0x8664,write=mode!='unwritten',error=mode=='api-error',false=mode=='false',missing=mode=='absent')
 try:namespace['_windows_machine']()
 except (ValueError,OSError,AttributeError):checks.append(mode)
 else:raise AssertionError(mode)
state.update(native=0x8664,process=0,write=True,error=False,false=False,missing=False)
from packaging import markers
outputs=[]
for wmi in ('AMD64',''):
 platform.machine=lambda:wmi
 markers._cached_default_environment.cache_clear()
 payload={'declarations':[{'kind':'python','name':'demo-a','constraint':'>=1'}],'site_packages':selected,'interpreter_root':''}
 sys.stdin=io.StringIO(json.dumps(payload));capture=io.StringIO();saved=sys.stdout;sys.stdout=capture
 try:namespace['main']()
 finally:sys.stdout=saved
 outputs.append(json.loads(capture.getvalue()))
assert outputs[0]==outputs[1]
assert outputs[0]['environment']['platform_machine']=='AMD64'
checks.append('full-probe-wmi-independent')
# A missing dependency conditional on the actual architecture must never be
# skipped just because WMI fails or ambient architecture variables are poisoned.
metadata=next(pathlib.Path(selected).glob('demo_a-*.dist-info/METADATA'))
metadata.write_text(metadata.read_text()+'Requires-Dist: missing-native; platform_machine == "AMD64"\n')
for wmi in ('AMD64',''):
 platform.machine=lambda:wmi
 markers._cached_default_environment.cache_clear()
 sys.stdin=io.StringIO(json.dumps(payload))
 try:namespace['main']()
 except ValueError:checks.append('conditional-missing-denied-'+('success' if wmi else 'failure'))
 else:raise AssertionError('architecture marker bypass')
print(json.dumps(checks))
`

func TestWindowsMarkerEnvironment(t *testing.T) {
	home := isolated(t)
	base := os.Getenv("M3C_DEPENDENCY_TEST_PYTHON")
	if base == "" {
		t.Skip("explicit fixture Python not selected")
	}
	setup, err := probe(context.Background(), Profile{ProjectRoot: home}, base, []string{"-I", "-B", "-c", pythonFixture, filepath.Join(home, "marker-env")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Path string `json:"path"`
		Site string `json:"site"`
	}
	if strictJSON(setup, &fixture) != nil {
		t.Fatal("fixture protocol")
	}
	input, err := json.Marshal(struct {
		Probe string `json:"probe"`
		Site  string `json:"site"`
	}{pythonProbe, fixture.Site})
	if err != nil {
		t.Fatal(err)
	}
	output, err := probe(context.Background(), Profile{ProjectRoot: home}, fixture.Path, []string{"-I", "-B", "-c", windowsMarkerFixture}, input)
	if err != nil {
		t.Fatal(err)
	}
	var checks []string
	if strictJSON(output, &checks) != nil || len(checks) != 16 {
		t.Fatalf("Windows marker simulation failed: %s", output)
	}
}
