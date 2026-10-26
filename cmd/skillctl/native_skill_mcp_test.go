package main

import (
	"bufio"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// TestNativeSkillRetainedMCPSubprocess exercises shipping Go through real MCP stdio.
func TestNativeSkillRetainedMCPSubprocess(t *testing.T) {
	required, present := os.LookupEnv("M3C_REQUIRE_NATIVE_MCP_TESTS")
	if present && required != "1" {
		t.Fatal("invalid native MCP producer requirement")
	}
	python := os.Getenv("M3C_MCP_TEST_PYTHON")
	if python == "" {
		if present {
			t.Fatal("required native MCP interpreter is missing")
		}
		t.Skip("outside required MCP producers: select M3C_MCP_TEST_PYTHON")
	}
	if !filepath.IsAbs(python) {
		t.Fatal("native MCP interpreter must be absolute")
	}
	if info, err := os.Stat(python); err != nil || !info.Mode().IsRegular() {
		t.Fatal("native MCP interpreter unavailable")
	}
	binary, flags, _ := qaNativeSourceBinary(t)
	module, err := filepath.Abs(filepath.Join("..", "..", "mcp-skill-server"))
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"confirm", "close", "wrong-token", "transport-EOF"} {
		t.Run(mode, func(t *testing.T) {
			f := qaNativeSkillCLINew(t)
			f.enroll(t, binary, flags)
			before := qaNativeSkillCLIInventory(t, f.source.base.home)
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			script := `import asyncio,json,os,sys
from mcp import ClientSession,StdioServerParameters
from mcp.client.stdio import stdio_client
async def main():
    params=StdioServerParameters(command=sys.executable,args=[os.path.join(sys.argv[1],'server.py')],env=dict(os.environ))
    async with stdio_client(params) as(reader,writer):
        async with ClientSession(reader,writer) as session:
            await session.initialize()
            async def call(name,args):
                result=await session.call_tool(name,args)
                values=[json.loads(item.text) for item in result.content if getattr(item,'type',None)=='text']
                assert len(values)==1,'MCP result is not one JSON object'
                return values[0]
            plan=await call('native_skill_install_plan',{'digest':sys.argv[3]})
            assert plan.get('ok') is True and plan.get('exit_code')==0 and plan.get('type')=='native-skill-plan','real signed plan refused'
            assert len(plan['rows'])==1 and plan['rows'][0]['Kind']=='skill' and plan['rows'][0]['Digest']==sys.argv[3]
            assert len(plan['token'])==43
            for tool,args in [('native_agent_install_confirm',{'token':plan['token']}),('native_agent_install_close',{})]:
                denied=await call(tool,args)
                assert denied.get('ok') is False and denied.get('exit_code')==12,'wrong-kind call consumed or used skill slot'
            blocked=await call('skill_install',{'name':'must-stay-native-blocked'})
            assert blocked.get('ok') is False and blocked.get('exit_code')==12,'generic native guard weakened'
            print('planned',flush=True)
            assert await asyncio.to_thread(sys.stdin.readline)=='continue\n','test driver control missing'
            mode=sys.argv[2]
            if mode=='confirm':
                done=await call('native_skill_install_confirm',{'token':plan['token']})
                assert done.get('ok') is True and done.get('exit_code')==0 and done.get('type')=='native-skill-installed','real held confirm failed'
                assert len(done['results'])==1 and done['results'][0]['SkillPath']==plan['rows'][0]['Target']
                replay=await call('native_skill_install_confirm',{'token':plan['token']})
                assert replay.get('ok') is False,'consumed confirmation replayed'
            elif mode=='close':
                done=await call('native_skill_install_close',{})
                assert done.get('ok') is True and done.get('closed') is True,'checked close failed'
            elif mode=='wrong-token':
                wrong='A'*43 if plan['token']!='A'*43 else 'B'*42+'A'
                done=await call('native_skill_install_confirm',{'token':wrong})
                assert done.get('ok') is False and done.get('exit_code')==12,('caller token replaced by retained token',{k:done.get(k) for k in ('exit_code','error_class','possible_change','stderr')})
    print('finished',flush=True)
asyncio.run(main())`
			cmd := exec.CommandContext(ctx, python, "-B", "-u", "-c", script, module, mode, f.digest)
			cmd.WaitDelay = time.Second
			cmd.Dir = f.source.base.project
			env := qaNativeSourceEnv(nativeCLIQAEnv(f.source.base.home), "GOFLAGS", flags)
			for key, value := range map[string]string{"SKILLCTL_BIN": binary, "SKILLCTL_ENTERPRISE_PROFILE": f.source.base.path, "SKILLCTL_PROJECT_ROOT": f.source.base.project, "SKILLCTL_ARTIFACT_HOME": f.source.base.home, "SKILLCTL_NATIVE_SKILL_INSTALL": "1", "M3C_REQUIRE_NATIVE_MCP_TESTS": "1", "M3C_MCP_TEST_PYTHON": python} {
				env = qaNativeSourceEnv(env, key, value)
			}
			cmd.Env = env
			input, e := cmd.StdinPipe()
			if e != nil {
				t.Fatal(e)
			}
			defer input.Close()
			output, e := cmd.StdoutPipe()
			if e != nil {
				t.Fatal(e)
			}
			var stderr strings.Builder
			cmd.Stderr = &stderr
			if e = cmd.Start(); e != nil {
				t.Fatal(e)
			}
			defer func() {
				if cmd.ProcessState == nil {
					_ = cmd.Process.Kill()
					_ = cmd.Wait()
				}
			}()
			failDriver := func(message string) {
				t.Helper()
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
				t.Fatal(message, stderr.String())
			}
			scanner := bufio.NewScanner(output)
			if !scanner.Scan() || scanner.Text() != "planned" {
				failDriver("actual MCP did not reach held plan")
			}
			if !reflect.DeepEqual(before, qaNativeSkillCLIInventory(t, f.source.base.home)) {
				t.Fatal("MCP plan published before client consent")
			}
			busy, stop := context.WithTimeout(context.Background(), 100*time.Millisecond)
			_, e = f.source.journal(t).Status(busy)
			stop()
			if !errors.Is(e, context.DeadlineExceeded) {
				t.Fatal("MCP did not retain actual Go journal lock", e)
			}
			if _, e = input.Write([]byte("continue\n")); e != nil {
				t.Fatal(e)
			}
			if !scanner.Scan() || scanner.Text() != "finished" {
				failDriver("actual MCP did not complete selected lifecycle")
			}
			if scanner.Scan() {
				t.Fatal("unexpected extra driver output")
			}
			if e = scanner.Err(); e != nil {
				t.Fatal(e)
			}
			if e = cmd.Wait(); e != nil || ctx.Err() != nil {
				t.Fatal("actual MCP child failed", e, stderr.String())
			}
			if mode == "confirm" {
				qaNativeSkillCLIFrame(t, f)
			} else if !reflect.DeepEqual(before, qaNativeSkillCLIInventory(t, f.source.base.home)) {
				t.Fatal("unconfirmed MCP session published artifacts")
			}
			released, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			if _, e = f.source.journal(t).Status(released); e != nil {
				t.Fatal("MCP lifecycle did not release journal", e)
			}
			if f.requests.Load() != 1 || f.source.requests.Load() != 0 || f.source.base.requests.Load() != 0 {
				t.Fatal("MCP used extra or unselected network source")
			}
		})
	}
}
