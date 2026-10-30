// Node built-in tests for the thin host transport. No model or target code is executed.
import test from 'node:test';
import assert from 'node:assert/strict';
import { copyFile, mkdtemp, readFile, rm, writeFile, symlink } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { createServer } from 'node:http';
import { operatorConfig, invocation, runScan, summarize } from './assets/shared/runner.mjs';
import { registerPi, openCodeDefinition } from './assets/shared/adapters.mjs';

const BIN = process.env.SCOUT_TEST_BIN;
const ROOT = resolve(import.meta.dirname, '../../..');
const base = (changes = {}) => ({ SCOUT_BIN: '/trusted/scout', SCOUT_TARGETS: '{"candidate":{"path":"/review/plugin","harness":"claude-code"}}', ...changes });
const reviewer = JSON.stringify({endpoint:'https://review.example/v1/chat/completions',model:'test',keyEnv:'REVIEW_KEY'});
const setup = (changes) => operatorConfig(base(changes));

await test('operator configuration is explicit, bounded and immutable', () => {
  const c = setup();
  assert.ok(Object.isFrozen(c)); assert.ok(Object.isFrozen(c.targets));
  assert.ok(Object.isFrozen(c.targets.candidate));
  assert.equal(c.reviewer, null); assert.equal(c.reduced,false);
  for (const change of [
    {SCOUT_BIN:'scout'}, {SCOUT_BIN:'/bad\npath'}, {SCOUT_TARGETS:'{}'},
    {SCOUT_TARGETS:'{"candidate":{"path":"relative"}}'},
    {SCOUT_TARGETS:'{"__proto__":{"path":"/tmp"}}'},
    {SCOUT_TARGETS:'{"candidate":{"path":"/tmp","baseline":"/file"}}'},
    {SCOUT_TARGETS:'{"candidate":{"path":"https://user:key@host/path"}}'},
    {SCOUT_TARGETS:'{"candidate":{"path":"https://host/p?token=secret"}}'},
    {SCOUT_TARGETS:'{"candidate":{"path":"/tmp","revision":"abc"}}'},
    {SCOUT_TARGETS:'{"candidate":{"path":"/tmp","harness":"invented"}}'},
    {SCOUT_REDUCED_CORE:'true'},
    {SCOUT_REVIEWER: JSON.stringify({endpoint:'http://localhost/review',model:'test'})},
    {SCOUT_REVIEWER: JSON.stringify({endpoint:'http://192.168.0.1/review',model:'test',allowLoopback:true})},
    {SCOUT_REVIEWER: JSON.stringify({endpoint:'https://x/review',model:'test',keyEnv:'$HOME'})},
    {SCOUT_REVIEWER: JSON.stringify({endpoint:'https://x/review',model:'test',provider:'executable'})},
  ]) assert.throws(() => setup(change),undefined,JSON.stringify(change));
  const loop = setup({SCOUT_REVIEWER: JSON.stringify({endpoint:'http://127.0.0.1:8080/v1/chat/completions',model:'test',allowLoopback:true})});
  assert.equal(loop.reviewer.allowLoopback,true);
});

await test('only named inputs and enumerated tool arguments are accepted', () => {
  const c=setup(); const p=invocation({target:'candidate'},c);
  assert.equal(p.semantic,false); assert.equal(p.args[0],'scan');
  assert.deepEqual(p.args.slice(-2),['--','/review/plugin']);
  assert.equal(p.args[p.args.indexOf('--profile')+1], 'standard');
  assert.equal(p.args[p.args.indexOf('--harness')+1], 'claude-code');
  for(const flag of ['--allow-download','--semantic','--vuln','--baseline','--output','--config']) assert.ok(!p.args.includes(flag));
  assert.deepEqual(p.grants.map(x=>x.permission),['bash','read','external_directory']);
  for(const args of [{target:'/etc/passwd'},{target:'--help'},{target:'candidate',args:['--baseline','x']},{target:'candidate',semantic:'true'},{target:'candidate',semantic:true},{target:'constructor'}]) assert.throws(()=>invocation(args,c));
  const reduced=invocation({target:'candidate'},setup({SCOUT_REDUCED_CORE:'1'}));
  assert.equal(reduced.args[reduced.args.indexOf('--profile')+1], 'custom');
  assert.equal(reduced.args[reduced.args.indexOf('--checks')+1], 'patterns');
});

await test('download and source upload have different grants and no implicit credentials', () => {
  const c=setup({SCOUT_TARGETS:JSON.stringify({candidate:{path:'https://github.com/example/repo',revision:'a'.repeat(40),sha256:'b'.repeat(64)}}),SCOUT_REVIEWER:reviewer});
  const p=invocation({target:'candidate',semantic:true},c);
  assert.equal(p.args[p.args.indexOf('--profile')+1], 'review');
  assert.equal(p.grants.filter(g=>g.permission==='webfetch').length,2);
  assert.ok(p.args.includes('--allow-download')); assert.ok(p.args.includes('--allow-source-upload'));
  assert.ok(p.args.includes('SCOUT_REVIEW_KEY')); assert.ok(!p.args.includes('REVIEW_KEY'));
  assert.equal(p.args[p.args.indexOf('--revision')+1],'a'.repeat(40));
  assert.ok(!p.args.includes('--allow-vulnerability-network'));
});

await test('denial and cancellation precede executable/credential access', async () => {
  const config=setup({SCOUT_REVIEWER:reviewer});
  let read=0; const env={get REVIEW_KEY(){read++;throw Error('credential accessed');}};
  await assert.rejects(runScan({target:'candidate',semantic:true},config,async()=>false,undefined,env),/declined/);
  await assert.rejects(runScan({target:'candidate',semantic:true},config,async()=>{throw Error('denied');},undefined,env),/denied/);
  await assert.rejects(runScan({target:'candidate'},config,null),/permission gate/);
  const ac=new AbortController();ac.abort();let gates=0;
  await assert.rejects(runScan({target:'candidate',semantic:true},config,async()=>{gates++;},ac.signal,env),/cancelled/);
  assert.equal(gates,0);assert.equal(read,0);
});

function report(decision='review', completeness='partial') {
  const state = completeness === 'partial' ? 'incomplete' : completeness;
  return {
    schema:'scout.report/v1',operation:'scan',
    run:{state,digest:`sha256:${'a'.repeat(64)}`,engine:{version:'fixture',rulepack_digest:`sha256:${'b'.repeat(64)}`},
      plan:{name:'standard',requested_profile:'standard',checks:[],egress:{}},problems:[],
      targets:[{id:'target-0',index:0,state,analysis:{schema_version:'0.15',engine_version:'fixture',profile:'test',coverage:{completeness},artifact:{snapshot_sha256:'1'.repeat(64)},findings:[],diagnostics:[],limitations:[]}}]},
    evaluation:{decision,run_digest:`sha256:${'a'.repeat(64)}`,policy_digest:`sha256:${'c'.repeat(64)}`,reasons:[],suppressed:[]},
  };
}
const analysis = d => d.run.targets[0].analysis;
const finding = (id='f0') => ({id,rule_id:'R1',severity:'high',location:{path:'SKILL.md',coordinates:'text',start_line:1,start_column:1,end_line:1,end_column:6,byte_start:0,byte_end:5},evidence:{file_sha256:'a'.repeat(64),span_sha256:'b'.repeat(64)}});
const source = () => ({path:'SKILL.md',sha256:'a'.repeat(64),span_sha256:'b'.repeat(64),byte_start:0,byte_end:5});
function sum(r,code) { const c=setup();return summarize({code,stdout:Buffer.from(JSON.stringify(r))},invocation({target:'candidate'},c),c); }
await test('valid exit 1/2 findings are retained; invalid exit/report pairs fail closed', () => {
  for(const [d,c,e] of [['allow','complete',0],['review','complete',1],['block','complete',1],['block','partial',2],['review','failed',2]]){
    const s=sum(report(d,c),e);assert.equal(s.decision,d);assert.equal(s.completeness,c);assert.equal(s.exit_code,e);assert.equal(s.install_authorized,false);
  }
  const empty=report('allow','complete');analysis(empty).findings=null;
  assert.equal(sum(empty,0).finding_count,0);
  for(const [r,c] of [[report('allow','partial'),2],[report(),0],[report('block','complete'),2],[{...report(),schema:'future'},2]]) assert.throws(()=>sum(r,c));
  const c=setup();for(const text of ['','secret stderr','{','{"schema_version":"0.15"}']) assert.throws(()=>summarize({code:2,stdout:Buffer.from(text)},invocation({target:'candidate'},c),c));
});

await test('v1 document validates scan identities, state and digest bindings without a legacy fallback', () => {
  const cases = [
    d => { d.operation='compare'; },
    d => { d.run.targets=[]; },
    d => { d.run.targets.push(structuredClone(d.run.targets[0])); },
    d => { d.run.targets[0].index=1; },
    d => { d.run.targets[0].id=''; },
    d => { d.run.targets[0].state='unknown'; },
    d => { d.run.state='unknown'; },
    d => { d.run.digest='a'.repeat(64); },
    d => { d.run.engine.rulepack_digest='sha256:invalid'; },
    d => { d.run.engine.rulepack_digest=[`sha256:${'b'.repeat(64)}`]; },
    d => { d.evaluation.run_digest=`sha256:${'d'.repeat(64)}`; },
    d => { d.evaluation.policy_digest='sha256:invalid'; },
    d => { d.run.plan.name='custom'; },
    d => { analysis(d).findings=[null]; },
    d => { delete analysis(d).findings; },
    d => { analysis(d).diagnostics=[null]; },
    d => { analysis(d).coverage.completeness='unknown'; },
  ];
  for (const mutate of cases) { const d=report();mutate(d);assert.throws(()=>sum(d,2)); }
  for (const mutate of [
    d => { d.run.targets[0].state='incomplete'; },
    d => { analysis(d).coverage.completeness='partial'; },
    d => { d.run.problems=[{code:'incomplete',phase:'scan'}]; },
  ]) { const d=report('allow','complete');mutate(d);assert.throws(()=>sum(d,0)); }
  const flat={schema_version:'0.15',engine_version:'fixture',policy:{decision:'allow'},coverage:{completeness:'complete'},artifact:{},findings:[]};
  assert.throws(()=>sum(flat,0));
  const d=report('block','complete');analysis(d).policy={decision:'allow'};
  assert.equal(sum(d,1).decision,'block');assert.equal(sum(d,1).scan_schema,'scout.report/v1');
});

await test('finding, trace and semantic source references require bounded structural evidence', () => {
  const cases = [
    f => { f.severity='invented'; }, f => { f.rule_id=''; }, f => { f.id=''; },
    f => { f.location.byte_start=-1; }, f => { f.location.byte_end=f.location.byte_start; },
    f => { f.location.byte_end=Number.MAX_SAFE_INTEGER+1; },
    f => { f.location.start_line='1'; }, f => { f.evidence.span_sha256='bad'; },
    f => { f.evidence.span_sha256=['b'.repeat(64)]; },
    f => { f.related_evidence=[{...source(),sha256:'bad'}]; },
    f => { f.trace=[{role:'source',location:{...f.location,byte_end:-1},evidence:f.evidence}]; },
  ];
  for (const mutate of cases) { const d=report();const f=finding();mutate(f);analysis(d).findings=[f];assert.throws(()=>sum(d,2)); }
  for (const field of ['proposals','assessments','proposal_assessments']) {
    const d=report();analysis(d).semantic={enabled:true,[field]:[{id:'p1',evidence:[{...source(),byte_start:7}]}]};
    assert.throws(()=>sum(d,2));
  }
  const d=report();const f=finding();f.related_evidence=[source()];f.trace=[{role:'source',location:f.location,evidence:f.evidence}];analysis(d).findings=[f];
  assert.equal(sum(d,2).finding_count,1);
  analysis(d).findings.push(structuredClone(f));assert.throws(()=>sum(d,2));
});

await test('bounded summary never includes scanner source prose or secret values', () => {
  const r=report('block','partial');
  analysis(r).findings=Array.from({length:40},(_,i)=>{const f=finding(`f${i}`);f.message='SECRET-IN-MESSAGE';f.source='SECRET-IN-SOURCE';f.location.path='evil\u001b[31m\u202Epath';f.evidence.source='SECRET-IN-EVIDENCE';return f;});
  analysis(r).diagnostics=Array.from({length:20},()=>({code:'limit',message:'SECRET-IN-ERROR'}));
  analysis(r).limitations=Array.from({length:12},()=> 'Scope limited');
  const s=sum(r,2); const text=JSON.stringify(s);
  assert.equal(s.finding_count,40);assert.equal(s.findings.length,32);assert.equal(s.omitted_findings,8);
  assert.equal(s.omitted_diagnostics,8);assert.equal(s.omitted_limitations,4);
  assert.equal(s.full_report_returned,false);assert.match(s.report_sha256,/^[0-9a-f]{64}$/);
  assert.ok(!text.includes('SECRET'));assert.ok(!text.includes('\u001b'));assert.ok(!text.includes('\u202e'));
});

const Type={Object:(v)=>v,String:()=>({}),Optional:v=>v,Boolean:()=>({})};
const chain=()=>({describe(){return this;},optional(){return this;}});
const tool=d=>d;tool.schema={string:chain,boolean:chain};
await test('inspection summary preserves selected checks and rejects arbitrary nested prose', () => {
  const c=setup();const p=invocation({target:'candidate'},c);const r=report();
  r.run.plan={name:'standard',requested_profile:'standard',checks:[{id:'python',selected:true,available:false,source:'SECRET'},{id:'invented',selected:true,source:'SECRET'}],egress:{source_upload:false}};
  const summary=summarize({code:2,stdout:Buffer.from(JSON.stringify(r))},p,c);
  assert.equal(summary.inspection.name,'standard');
  assert.deepEqual(summary.inspection.checks,[{id:'python',selected:true,available:false}]);
  assert.ok(!JSON.stringify(summary).includes('SECRET'));
});

await test('Pi requires interactive confirmations and has no permission fallback',async()=>{
  let def;registerPi({registerTool:d=>{def=d;}},Type,base());assert.equal(def.name,'scout_scan');
  await assert.rejects(def.execute('1',{target:'candidate'},undefined,null,{hasUI:false}),/permission gate/);
  let gates=0;await assert.rejects(def.execute('1',{target:'candidate'},undefined,null,{hasUI:true,ui:{confirm:async()=>{gates++;return false;}}}),/declined/);assert.equal(gates,1);
});
await test('OpenCode permission denial uses no persistent wildcard grants',async()=>{
  const def=openCodeDefinition(tool,base());
  await assert.rejects(def.execute({target:'candidate'},{}),/permission gate/);
  let grant;await assert.rejects(def.execute({target:'candidate'},{ask:async g=>{grant=g;return false;}}),/declined/);
  assert.deepEqual(grant.always,[]);assert.equal(grant.permission,'bash');assert.equal(grant.metadata.tool,'scout_scan');
});

if(!BIN) {
  await test('real scanner CLI integration', {skip:'Set SCOUT_TEST_BIN to an explicitly built trusted scanner; skipped is NOT end-to-end acceptance.'},()=>{});
} else {
  const realenv = (path, extra={}) => base({SCOUT_BIN:BIN,SCOUT_TARGETS:JSON.stringify({candidate:{path,harness:'claude-code'}}),SCOUT_REDUCED_CORE:'0',...extra});
  await test('real Go CLI returns allow for simple text through transport',async()=>{
    const env=realenv(join(ROOT,'testdata/plain'), {SCOUT_TARGETS:JSON.stringify({candidate:{path:join(ROOT,'testdata/plain'),harness:'agent-skills'}})});
    let calls=0;const s=await runScan({target:'candidate'},operatorConfig(env),async()=>{calls++;},undefined,env);
    assert.equal(calls,3);assert.equal(s.decision,'allow');assert.equal(s.completeness,'complete');assert.equal(s.exit_code,0);assert.equal(s.reduced_core_requested,false);
    assert.equal(s.inspection.name,'standard');
    for(const id of ['python','yaml','toml','yara']) assert.deepEqual(s.inspection.checks.find(c=>c.id===id),{id,selected:true,available:true});
  });
  await test('real Go CLI preserves block/partial evidence through Pi and OpenCode',async()=>{
    const env=realenv(join(ROOT,'testdata/mvp-plugin'));
    let def;registerPi({registerTool:d=>{def=d;}},Type,env);let confirms=0;
    const a=await def.execute('case',{target:'candidate'},undefined,null,{hasUI:true,ui:{confirm:async()=>{confirms++;return true;}}});
    const p=JSON.parse(a.content[0].text);assert.equal(p.decision,'block');assert.equal(p.completeness,'partial');assert.equal(p.exit_code,2);assert.equal(confirms,3);
    assert.ok(p.findings.some(f=>f.rule_id==='GO004'));
    let grants=[];const o=JSON.parse(await openCodeDefinition(tool,env).execute({target:'candidate'},{ask:async g=>{grants.push(g);}}));
    assert.equal(o.decision,'block');assert.deepEqual(o.findings,p.findings);assert.equal(grants.length,3);
  });
  await test('operator can explicitly select custom checks without changing standard defaults',async()=>{
    const env=realenv(join(ROOT,'testdata/port-extension'),{SCOUT_REDUCED_CORE:'1'});
    const s=await runScan({target:'candidate'},operatorConfig(env),async()=>{},undefined,env);
    assert.equal(s.reduced_core_requested,true);assert.equal(s.inspection.name,'custom');
    for(const id of ['python','yaml','toml','yara']) assert.equal(s.inspection.checks.find(c=>c.id===id).selected,false);
  });
  await test('target path shell metacharacters are passed as one argument, never executed',async()=>{
    const d=await mkdtemp(join(tmpdir(),'scout-argv-'));
    try {
      const file=join(d,'$(touch OWNED);target.txt');await writeFile(file,'Ordinary text.');
      const env=realenv(file);const s=await runScan({target:'candidate'},operatorConfig(env),async()=>{},undefined,env);
      assert.equal(s.finding_count,0);await assert.rejects(readFile(join(d,'OWNED')),{code:'ENOENT'});
    } finally {await rm(d,{recursive:true,force:true});}
  });
  await test('target-supplied and symlink scanner binaries are rejected',async()=>{
    const d=await mkdtemp(join(tmpdir(),'scout-exe-'));
    try {
      const copy=join(d,'scout');await copyFile(BIN,copy);
      const env=realenv(d,{SCOUT_BIN:copy});
      await assert.rejects(runScan({target:'candidate'},operatorConfig(env),async()=>{},undefined,env),/supplied by the target/);
      const link=join(d,'link');await symlink(BIN,link);env.SCOUT_BIN=link;
      await assert.rejects(runScan({target:'candidate'},operatorConfig(env),async()=>{},undefined,env),/symlink/);
    } finally {await rm(d,{recursive:true,force:true});}
  });
  await test('concurrent transport calls do not share source or policy state',async()=>{
    const a=realenv(join(ROOT,'testdata/plain'),{SCOUT_TARGETS:JSON.stringify({candidate:{path:join(ROOT,'testdata/plain'),harness:'agent-skills'}})});
    const b=realenv(join(ROOT,'testdata/mvp-plugin'));
    const results=await Promise.all([a,b,a,b].map(env=>runScan({target:'candidate'},operatorConfig(env),async()=>{},undefined,env)));
    assert.deepEqual(results.map(r=>r.decision),['allow','block','allow','block']);
  });
  await test('real semantic HTTP path is separately authorized and preserves model evidence',async()=>{
    const dir=await mkdtemp(join(tmpdir(),'scout-model-'));
    await writeFile(join(dir,'SKILL.md'),'TypeScript query example; confidential-source-sentinel.\n```ts\ndb.query("SELECT name FROM accounts WHERE id = " + input);\n```\n');
    let calls=0,reads=0;const errors=[];
    const server=createServer(async(req,res)=>{
      try {
        calls++;assert.equal(req.headers.authorization,'Bearer operator-key-sentinel');
        const parts=[];for await(const part of req)parts.push(part);
        const wire=JSON.parse(Buffer.concat(parts));const input=JSON.parse(wire.messages[1].content);
        assert.equal(wire.tool_choice,'none');assert.deepEqual(wire.tools,[]);
        const response={schema_version:input.schema_version,request_id:input.request_id,proposals:[],assessments:[]};
        if(input.mode==='discovery'){
          const ex=input.excerpts[0];response.proposals.push({reason:'knowledge:K-SQL-PARAMS',severity:'high',evidence:[{excerpt_id:ex.id,sha256:ex.sha256}]});
        }
        for(const f of input.findings) response.assessments.push({finding_id:f.id,verdict:'confirmed',reason:'supported_by_context',evidence:f.evidence});
        res.setHeader('Content-Type','application/json');
        res.end(JSON.stringify({model:'fixture',choices:[{index:0,finish_reason:'stop',message:{role:'assistant',content:JSON.stringify(response)}}]}));
      }catch(e){errors.push(e.message);res.statusCode=500;res.end('{}');}
    });
    await new Promise(r=>server.listen(0,'127.0.0.1',r));
    try{
      const endpoint=`http://127.0.0.1:${server.address().port}/v1/chat/completions`;
      const env=realenv(dir,{SCOUT_TARGETS:JSON.stringify({candidate:{path:dir,harness:'agent-skills'}}),SCOUT_REVIEWER:JSON.stringify({endpoint,model:'fixture',keyEnv:'REVIEW_KEY',allowLoopback:true})});
      Object.defineProperty(env,'REVIEW_KEY',{get(){reads++;return 'operator-key-sentinel';}});
      const config=operatorConfig(env);let granted=[];
      await assert.rejects(runScan({target:'candidate',semantic:true},config,async g=>g.permission!=='webfetch',undefined,env),/declined/);
      assert.equal(calls,0);assert.equal(reads,0);
      const result=await runScan({target:'candidate',semantic:true},config,async g=>{granted.push(g);},undefined,env);
      assert.deepEqual(errors,[]);assert.equal(reads,1);assert.ok(calls>=3);
      assert.equal(granted.length,4);assert.equal(result.decision,'block');assert.equal(result.exit_code,2);
      assert.ok(result.findings.some(f=>f.rule_id==='JS004'));
      assert.equal(result.semantic.completeness,'complete');assert.equal(result.completeness,'partial');
      assert.ok(result.diagnostics.some(d=>d.code==='metadata_contract_partial'));
      assert.equal(result.semantic_requested,true);assert.ok(result.semantic_proposal_count>0);
      assert.equal(result.semantic.proposals[0].reason,'knowledge:K-SQL-PARAMS');
      assert.equal(result.semantic.proposals[0].knowledge_topic_id,'K-SQL-PARAMS');
      assert.equal(result.semantic.proposal_assessments[0].verdict,'confirmed');
      const text=JSON.stringify(result);assert.ok(!text.includes('operator-key-sentinel'));assert.ok(!text.includes('confidential-source-sentinel'));
    }finally{server.closeAllConnections();await new Promise(r=>server.close(r));await rm(dir,{recursive:true,force:true});}
  });

}

await test('trusted process failures are bounded and never become admission results', async () => {
  const dir=await mkdtemp(join(tmpdir(),'scout-transport-fixture-'));
  const target=join(dir,'candidate');
  try {
    for (const [name,body,expected] of [
      ['exit',"process.exit(3)",/terminated without a valid review result/],
      ['signal',"process.kill(process.pid, 'SIGTERM')",/terminated without a valid review result/],
      ['stdout',"process.stdout.write(Buffer.alloc(9*1024*1024));setTimeout(()=>{},1000)",/report exceeds transport limit/],
      ['stderr',"process.stderr.write(Buffer.alloc(70*1024));setTimeout(()=>{},1000)",/diagnostics exceed transport limit/],
      ['utf8',"process.stdout.write(Buffer.from([255]));",/valid UTF-8 JSON report/],
    ]) {
      const binary=join(dir,name);
      await writeFile(binary,`#!${process.execPath}\n${body}\n`,{mode:0o700});
      const config=setup({SCOUT_BIN:binary,SCOUT_TARGETS:JSON.stringify({candidate:{path:target}})});
      await assert.rejects(runScan({target:'candidate'},config,async()=>true),expected);
    }
    const binary=join(dir,'missing-interpreter');
    await writeFile(binary,'#!/definitely-missing-scout-interpreter\n',{mode:0o700});
    const config=setup({SCOUT_BIN:binary,SCOUT_TARGETS:JSON.stringify({candidate:{path:target}})});
    await assert.rejects(runScan({target:'candidate'},config,async()=>true),/could not be started/);
  } finally {await rm(dir,{recursive:true,force:true});}
});

await test('cancellation stops a running trusted scanner after all grants', async () => {
  const dir=await mkdtemp(join(tmpdir(),'scout-cancel-fixture-'));
  const marker=join(dir,'started'),binary=join(dir,'trusted'),cancel=new AbortController();
  try {
    await writeFile(binary,`#!${process.execPath}\nimport { writeFileSync } from 'node:fs';writeFileSync(${JSON.stringify(marker)},'started');setInterval(()=>{},1000);\n`,{mode:0o700});
    const config=setup({SCOUT_BIN:binary,SCOUT_TARGETS:JSON.stringify({candidate:{path:join(dir,'candidate')}})});
    let grants=0;
    const result=runScan({target:'candidate'},config,async()=>{grants++;return true;},cancel.signal);
    const rejection=assert.rejects(result,/Review cancelled/);
    for(let i=0;i<100;i++){
      if(await readFile(marker).then(()=>true,()=>false))break;
      await new Promise(resolve=>setTimeout(resolve,5));
    }
    assert.equal(await readFile(marker,'utf8'),'started');
    cancel.abort();await rejection;
    assert.equal(grants,3);
  } finally {cancel.abort();await rm(dir,{recursive:true,force:true});}
});

await test('analysis identities and coverage are validated before summary projection', () => {
  for(const mutate of [
    d=>{analysis(d).coverage=null;},
    d=>{analysis(d).artifact=null;},
    d=>{analysis(d).engine_version='different-engine';},
    d=>{analysis(d).artifact.snapshot_sha256='invalid';},
  ]) {
    const document=report();mutate(document);
    assert.throws(()=>sum(document,2));
  }
});
