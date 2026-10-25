package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestInstallEnterpriseProfileMCPSubprocess uses the actual built CLI and MCP wire.
func TestInstallEnterpriseProfileMCPSubprocess(t *testing.T) {
	python := os.Getenv("M3C_MCP_TEST_PYTHON")
	if python == "" {
		t.Skip("run through the MCP suite with its explicit interpreter")
	}
	binary := skillctlBin(t)
	f := registryMutationFixture(t)
	list := mutationCLIList(t, f, "initial", 1, time.Now().Add(-time.Hour))
	enrollStateCLI(t, binary, f, list)
	project := t.TempDir()
	profile, _ := enterpriseInstallFixtureProfile(t, f, project)
	module, err := filepath.Abs(filepath.Join("..", "..", "mcp-skill-server"))
	if err != nil {
		t.Fatal(err)
	}
	script := `import asyncio,json,os,pathlib,sys
sys.path.insert(0,sys.argv[1])
import server
from mcp import ClientSession,StdioServerParameters
from mcp.client.stdio import stdio_client
async def main():
    direct=await server.skill_install('fetch-contract',version='1.0.0')
    assert direct['ok'] and direct['install_path'],direct
    for fields in ({'enterprise_profile':'/client/foreign'},{'registry':'https://foreign.invalid'},{'ignore_deps':True}):
        result=await server.skill_install('fetch-contract',**fields)
        assert not result['ok'] and result['exit_code']==12,result
    params=StdioServerParameters(command=sys.executable,args=[os.path.join(sys.argv[1],'server.py')],env=dict(os.environ))
    async with stdio_client(params) as(reader,writer):
        async with ClientSession(reader,writer) as session:
            await session.initialize()
            listed=await session.list_tools()
            assert 'skill_install' in [tool.name for tool in listed.tools]
            async def call(fields):
                result=await session.call_tool('skill_install',fields)
                values=[json.loads(item.text) for item in result.content if getattr(item,'type',None)=='text']
                assert len(values)==1,result
                return values[0]
            installed=await call({'name':'fetch-contract','version':'1.0.0'})
            assert installed['ok'] and installed['digest']==direct['digest'],installed
            refused=await call({'name':'fetch-contract','enterprise_profile':'/client/foreign'})
            assert not refused['ok'] and refused['exit_code']==12,refused
            path=pathlib.Path(os.environ['SKILLCTL_ENTERPRISE_PROFILE']);path.write_bytes(path.read_bytes()+b' ')
            drift=await call({'name':'fetch-contract'})
            assert not drift['ok'] and drift['exit_code']==12,drift
    print('enterprise-built-CLI-and-MCP-stdio-pass')
asyncio.run(main())`
	cmd := exec.Command(python, "-B", "-c", script, module)
	cmd.Dir = project
	cmd.Env = append(os.Environ(), "HOME="+f.home, "USERPROFILE="+f.home, "M3C_TOKEN_STORE=file", "M3C_TEST_KEYCHAIN=0", "M3C_ER1_KEYCHAIN=off", "SKILLCTL_BIN="+binary, "SKILLCTL_ENTERPRISE_PROFILE="+profile, "SKILLCTL_PROJECT_ROOT="+project, "SKILLCTL_ARTIFACT_HOME="+f.home)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("actual CLI/MCP process: %v\n%s", err, out)
	}
}
