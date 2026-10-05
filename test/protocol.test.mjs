import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createVoidmailServer } from '../dist/server.js';
import { requestJson } from '../dist/request.js';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const syntheticKey = 'vm_' + 'a'.repeat(64);
async function fixture(t, fetcher, apiKey = syntheticKey) {
  // Key files go to a throwaway directory, never the real home directory.
  const keyRoot = mkdtempSync(join(tmpdir(), 'voidmail-protocol-'));
  const server = createVoidmailServer({ fetch: fetcher, apiKey, keyRoot });
  const client = new Client({ name: 'synthetic-email-check', version: '1' });
  const [left, right] = InMemoryTransport.createLinkedPair();
  await server.connect(left); await client.connect(right);
  t.after(async () => { await client.close(); await server.close(); rmSync(keyRoot, { recursive: true, force: true }); });
  return client;
}

test('protocol inventories 19 tools and 3 resources with truthful side-effect hints', async t => {
  const client = await fixture(t, () => { throw new Error('No network expected'); });
  assert.equal(client.getServerVersion().version, '1.2.1');
  const { tools } = await client.listTools(); assert.equal(tools.length, 19);
  const byName = Object.fromEntries(tools.map(x => [x.name, x]));
  assert.equal(byName.voidmail_account_info.annotations.readOnlyHint, true);
  assert.equal(byName.voidmail_read_email.annotations.readOnlyHint, false);
  assert.equal(byName.voidmail_send_email.annotations.readOnlyHint, false);
  assert.equal(byName.voidmail_send_email.annotations.idempotentHint, false);
  assert.equal(byName.voidmail_create_account.annotations.idempotentHint, false);
  for (const name of ['delete_email', 'delete_alias', 'set_webhook', 'revoke_recipient']) assert.equal(byName['voidmail_' + name].annotations.destructiveHint, true);
  assert.equal(byName.voidmail_policy.annotations.readOnlyHint, true);
  assert.equal(byName.voidmail_request_recipient.annotations.readOnlyHint, false);
  const createAddress = byName.voidmail_create_account.inputSchema.properties.address;
  assert.match(createAddress.description, /local part/);
  assert.equal(createAddress.minLength, 3); assert.equal(createAddress.maxLength, 42);
  const listLimit = byName.voidmail_list_inbox.inputSchema.properties.limit;
  assert.equal(listLimit.maximum, 100); assert.match(listLimit.description, /default 50/);
  const search = byName.voidmail_search_inbox.inputSchema.properties;
  assert.equal(search.query.minLength, 1);
  assert.equal(search.limit.maximum, 50); assert.match(search.limit.description, /default 20/);
  assert.match(byName.voidmail_set_webhook.description, /allowlist inbox.*owner\/webhook.*owner key/);
  assert.match(byName.voidmail_send_email.description, /Legacy send.*Prefer voidmail_send_once/);
  assert.match(byName.voidmail_send_once.description, /Preferred send/);
  assert.equal((await client.listResources()).resources.length, 3);
});

test('create accepts its own full address but sends only a local part to the API', async t => {
  const calls = [];
  const client = await fixture(t, async (url, init) => {
    calls.push({ url, init });
    return Response.json({ address: 'contractcase@voidmail.ai', api_key: 'vm_' + 'b'.repeat(64), owner_key: 'vmo_' + 'A'.repeat(40), recipient_policy: 'allowlist' }, { status: 201 });
  }, null);
  for (const address of ['ab', 'a..b', '123abc', 'contractcase@example.com']) {
    const result = await client.callTool({ name: 'voidmail_create_account', arguments: { address } });
    assert.equal(result.isError, true, address);
  }
  assert.equal(calls.length, 0);
  const result = await client.callTool({ name: 'voidmail_create_account', arguments: { address: 'CONTRACTCASE@VOIDMAIL.AI' } });
  assert.notEqual(result.isError, true, result.content?.[0]?.text);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, 'https://api.voidly.ai/v1/agent-mail/create');
  assert.deepEqual(JSON.parse(calls[0].init.body), { name: 'agent', address: 'contractcase', recipient_policy: 'allowlist' });
  assert.equal(JSON.parse(result.content[0].text).address, 'contractcase@voidmail.ai');
  assert.doesNotMatch(JSON.stringify(result), /vm_bbbb|vmo_AAAA/);
});

test('send is a single authenticated request, acceptance is retained as returned', async t => {
  const calls = [];
  const client = await fixture(t, async (url, init) => {
    calls.push({url, init}); return Response.json({ success: true, id: 'synthetic-accepted' });
  });
  const result = await client.callTool({ name: 'voidmail_send_email', arguments: {to:'recipient@example.com', subject:'Synthetic', text:'Not actually sent'} });
  assert.equal(calls.length, 1); assert.equal(calls[0].url, 'https://api.voidly.ai/v1/agent-mail/send');
  assert.equal(calls[0].init.headers['X-Agent-Mail-Key'], syntheticKey);
  assert.equal(calls[0].init.redirect, 'error');
  assert.equal(JSON.parse(result.content[0].text).id, 'synthetic-accepted');
});

test('uncertain send returns protocol error, redacts transport data and never retries', async t => {
  let calls = 0;
  const client = await fixture(t, async () => { calls++; throw new Error(syntheticKey); });
  const result = await client.callTool({ name: 'voidmail_send_email', arguments: {to:'recipient@example.com',subject:'Test',text:'Synthetic'} });
  assert.equal(result.isError, true); assert.equal(calls, 1);
  assert.match(result.content[0].text, /outcome may be unknown/);
  assert.doesNotMatch(JSON.stringify(result), /vm_aaaa/);
});

test('failed account creation is an MCP error and does not install returned untrusted key', async t => {
  let calls = 0;
  const client = await fixture(t, async () => { calls++; return Response.json({api_key:syntheticKey,address:'synthetic@voidmail.ai'}, {status:500}); }, null);
  const result = await client.callTool({name:'voidmail_create_account',arguments:{}});
  assert.equal(result.isError, true); assert.equal(calls, 1);
  const account = await client.callTool({name:'voidmail_account_info',arguments:{}});
  assert.equal(account.isError, true); assert.equal(calls, 1);
});

test('path IDs cannot add query parameters or escape the inbox path', async t => {
  let actual;
  const client = await fixture(t, async url => { actual = url; return Response.json({id:'synthetic'}); });
  await client.callTool({name:'voidmail_read_email',arguments:{email_id:'../stats?private=1#x'}});
  assert.equal(actual, 'https://api.voidly.ai/v1/agent-mail/inbox/..%2Fstats%3Fprivate%3D1%23x');
});

test('invalid pagination never reaches the API', async t => {
  const calls = [];
  const client = await fixture(t, async url => { calls.push(url); return Response.json({ results: [] }); });
  for (const limit of [-1, 0, 101, 1.5]) {
    const result = await client.callTool({name:'voidmail_list_inbox',arguments:{limit}});
    assert.equal(result.isError, true);
  }
  for (const args of [{ query: 'invoice', limit: 0 }, { query: 'invoice', limit: 51 }, { query: 'invoice', limit: 1.5 }, { query: '' }, { query: '   ' }]) {
    const result = await client.callTool({ name: 'voidmail_search_inbox', arguments: args });
    assert.equal(result.isError, true, JSON.stringify(args));
  }
  assert.equal(calls.length, 0);
  await client.callTool({ name: 'voidmail_search_inbox', arguments: { query: ' invoice ', limit: 50 } });
  assert.equal(calls.length, 1);
  assert.equal(calls[0], 'https://api.voidly.ai/v1/agent-mail/inbox/search?q=invoice&limit=50');
});

test('deadline aborts one pending request without a retry', async () => {
  let calls = 0;
  await assert.rejects(requestJson(async (_url, {signal}) => {
    calls++;
    return new Promise((_, reject) => signal.addEventListener('abort', () => reject(new Error('timeout')), {once:true}));
  }, 'https://api.voidly.ai/synthetic', {method:'POST'}, 10), /outcome may be unknown/);
  assert.equal(calls, 1);
});

test('oversized responses cancel the reader', async () => {
  let cancelled = false;
  const stream = new ReadableStream({pull(c) { c.enqueue(new Uint8Array(1024*1024)); }, cancel() {cancelled=true;} });
  await assert.rejects(requestJson(async () => new Response(stream), 'https://api.voidly.ai/synthetic', {method:'GET'}), /2 MiB/);
  assert.equal(cancelled, true);
});

test('invalid JSON from a mutation has an uncertain outcome and no automatic retry', async () => {
  let calls = 0;
  await assert.rejects(requestJson(async () => {calls++;return new Response('<html>error</html>');}, 'https://api.voidly.ai/synthetic', {method:'POST'}), /outcome may be unknown/);
  assert.equal(calls, 1);
});

test('dot-only path identifiers never reach the API', async t => {
  let calls = 0;
  const client = await fixture(t, async () => { calls++; return Response.json({}); });
  for (const email_id of ['.', '..']) assert.equal((await client.callTool({name:'voidmail_read_email',arguments:{email_id}})).isError, true);
  assert.equal(calls, 0);
});

test('API failures retain status but never echo server-controlled errors', async t => {
  const client = await fixture(t, async () => Response.json({error:syntheticKey}, {status:401}));
  const result = await client.callTool({name:'voidmail_account_info',arguments:{}});
  assert.equal(result.isError, true); assert.match(result.content[0].text, /HTTP 401/);
  assert.doesNotMatch(JSON.stringify(result), /vm_aaaa/);
});

test('sending limits are discoverable as a read-only tool without sending', async t => {
  const calls=[]; const client=await fixture(t,async (url,init)=>{calls.push({url,init});return Response.json({mailboxPerDay:100});},null);
  const tools=await client.listTools();assert.equal(tools.tools.find(x=>x.name==='voidmail_sending_limits').annotations.readOnlyHint,true);
  const result=await client.callTool({name:'voidmail_sending_limits',arguments:{}});
  assert.equal(JSON.parse(result.content[0].text).mailboxPerDay,100);
  assert.equal(calls[0].url,'https://api.voidly.ai/v1/agent-mail/limits');assert.equal(calls[0].init.method,'GET');assert.equal(calls[0].init.headers['X-Agent-Mail-Key'],undefined);
});
test('rate limiting gives an agent the server cooldown without echoing error bodies or retrying', async t => {
  let calls=0;const client=await fixture(t,async()=>{calls++;return Response.json({secret:syntheticKey},{status:429,headers:{'Retry-After':'61'}});});
  const result=await client.callTool({name:'voidmail_send_email',arguments:{to:'recipient@example.com',subject:'Synthetic',text:'not sent'}});
  assert.equal(result.isError,true);assert.match(result.content[0].text,/61 seconds/);assert.match(result.content[0].text,/HTTP 429/);
  assert.doesNotMatch(result.content[0].text,/vm_aaaa/);assert.equal(calls,1);
});


test('durable send uses the saved original ID once and lookup is read-only', async t => {
  const calls=[];const operationId='original_operation_00001';
  const client=await fixture(t,async(url,init)=>{calls.push({url,init});return Response.json({operationId,status:'accepted',messageId:'provider-id',automatic_retry:false});});
  const result=await client.callTool({name:'voidmail_send_once',arguments:{operationId,to:'one@example.invalid',subject:'Synthetic',text:'Not sent'}});
  assert.equal(result.isError,false);assert.equal(calls.length,1);assert.equal(JSON.parse(calls[0].init.body).operationId,operationId);assert.equal(calls[0].url,'https://api.voidly.ai/v1/agent-mail/outbound');
  await client.callTool({name:'voidmail_send_status',arguments:{operationId}});assert.equal(calls.length,2);assert.equal(calls[1].init.method,'GET');assert.equal(calls[1].init.body,undefined);
  const tools=await client.listTools();assert.equal(tools.tools.find(x=>x.name==='voidmail_send_once').annotations.idempotentHint,true);assert.equal(tools.tools.find(x=>x.name==='voidmail_send_status').annotations.readOnlyHint,true);
});
test('durable uncertainty preserves the ID and never auto-retries', async t=>{
 let calls=0;const operationId='original_operation_00002';const client=await fixture(t,async()=>{calls++;throw new Error(syntheticKey);});
 const result=await client.callTool({name:'voidmail_send_once',arguments:{operationId,to:'one@example.invalid',subject:'Synthetic'}});assert.equal(result.isError,true);assert.equal(calls,1);assert.match(result.content[0].text,new RegExp(operationId));assert.doesNotMatch(result.content[0].text,/vm_aaaa/);
});
test('durable tools reject malformed operation IDs before network access',async t=>{
 let calls=0;const client=await fixture(t,async()=>{calls++;return Response.json({});});
 for(const operationId of ['short','../outbound?token=x','x'.repeat(129)]){const result=await client.callTool({name:'voidmail_send_status',arguments:{operationId}});assert.equal(result.isError,true);}assert.equal(calls,0);
});
test('durable send rejects a mismatched returned original',async t=>{
 const operationId='original_operation_00003';const client=await fixture(t,async()=>Response.json({operationId:'wrong_original_0000001',status:'accepted',messageId:'provider-id',automatic_retry:false}));
 const result=await client.callTool({name:'voidmail_send_once',arguments:{operationId,to:'one@example.invalid',subject:'Synthetic'}});assert.equal(result.isError,true);
});
test('pending durable response is not reported as successful acceptance',async t=>{
 const operationId='original_operation_00004';const client=await fixture(t,async()=>Response.json({operationId,status:'outcome_unknown',automatic_retry:false},{status:202}));
 const result=await client.callTool({name:'voidmail_send_once',arguments:{operationId,to:'one@example.invalid',subject:'Synthetic'}});assert.equal(result.isError,true);assert.equal(JSON.parse(result.content[0].text).status,'outcome_unknown');
});

test('durable throttling preserves safe server wait guidance and the original ID',async t=>{
 const operationId='original_operation_00005';let calls=0;const client=await fixture(t,async()=>{calls++;return Response.json({private:'do not echo'}, {status:429,headers:{'Retry-After':'45'}});});
 const result=await client.callTool({name:'voidmail_send_once',arguments:{operationId,to:'one@example.invalid',subject:'Synthetic'}});assert.equal(result.isError,true);assert.match(result.content[0].text,/45 seconds/);assert.match(result.content[0].text,new RegExp(operationId));assert.doesNotMatch(result.content[0].text,/do not echo/);assert.equal(calls,1);
});
