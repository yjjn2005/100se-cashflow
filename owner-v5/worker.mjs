/* Source draft for review and deployment testing. No live resources created. */
import {validate} from './public/model.mjs';
let keyCache={origin:'',until:0,keys:[]};
const decode=s=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-s.length%4)%4)),c=>c.charCodeAt(0));
export async function verifyIdentity(request,env,fetcher=fetch){
 if(!env.ACCESS_TEAM_DOMAIN||!env.ACCESS_AUD||!env.OWNER_EMAIL)throw Error('AUTH_NOT_CONFIGURED');
 const origin='https://'+env.ACCESS_TEAM_DOMAIN.replace(/^https?:\/\//,'').replace(/\/$/,'');if(!/^https:\/\/[a-zA-Z0-9-]+\.cloudflareaccess\.com$/.test(origin))throw Error('BAD_ACCESS_ORIGIN');
 const token=request.headers.get('Cf-Access-Jwt-Assertion');if(!token||token.length>16000)throw Error('UNAUTHORIZED');const parts=token.split('.');if(parts.length!==3)throw Error('UNAUTHORIZED');
 let header,payload;try{header=JSON.parse(new TextDecoder().decode(decode(parts[0])));payload=JSON.parse(new TextDecoder().decode(decode(parts[1])));}catch{throw Error('UNAUTHORIZED');}
 const now=Math.floor(Date.now()/1000);if(header.alg!=='RS256'||!header.kid||payload.iss!==origin||typeof payload.exp!=='number'||payload.exp<=now||typeof payload.iat!=='number'||payload.iat>now+60||(payload.nbf&&payload.nbf>now+60))throw Error('UNAUTHORIZED');
 const audience=Array.isArray(payload.aud)?payload.aud:[payload.aud];if(!audience.includes(env.ACCESS_AUD))throw Error('UNAUTHORIZED');
 if(payload.email?.toLowerCase()!==env.OWNER_EMAIL.toLowerCase()||(typeof payload.sub!=='string'||payload.sub.length<1))throw Error('FORBIDDEN');
 if(keyCache.origin!==origin||Date.now()>keyCache.until){const r=await fetcher(origin+'/cdn-cgi/access/certs',{headers:{Accept:'application/json'},cache:'no-store'});if(!r.ok)throw Error('AUTH_KEYS_UNAVAILABLE');const k=await r.json();if(!Array.isArray(k.keys))throw Error('AUTH_KEYS_UNAVAILABLE');keyCache={origin,until:Date.now()+300000,keys:k.keys};}
 const jwk=keyCache.keys.find(k=>k.kid===header.kid&&k.kty==='RSA');if(!jwk)throw Error('UNAUTHORIZED');const key=await crypto.subtle.importKey('jwk',jwk,{name:'RSASSA-PKCS1-v1_5',hash:'SHA-256'},false,['verify']);const ok=await crypto.subtle.verify('RSASSA-PKCS1-v1_5',key,decode(parts[2]),new TextEncoder().encode(parts[0]+'.'+parts[1]));if(!ok)throw Error('UNAUTHORIZED');
 return {owner:env.OWNER_EMAIL.toLowerCase(),subject:payload.sub};
}
export default {async fetch(request,env){const url=new URL(request.url);const headers={'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store, private','Pragma':'no-cache','X-Content-Type-Options':'nosniff','Vary':'Cf-Access-Jwt-Assertion'};const json=(body,status=200)=>new Response(JSON.stringify(body),{status,headers});
 let id;try{id=await verifyIdentity(request,env);}catch(e){const conf=e.message.includes('CONFIGURED')||e.message.includes('UNAVAILABLE')||e.message==='BAD_ACCESS_ORIGIN';return json({error:conf?'AUTH_UNAVAILABLE':'UNAUTHORIZED'},conf?503:401);}
 if(!url.pathname.startsWith('/api/')){if(!env.ASSETS)return json({error:'ASSETS_NOT_CONFIGURED'},503);const r=await env.ASSETS.fetch(request);const h=new Headers(r.headers);h.set('Cache-Control','no-store, private');h.set('X-Content-Type-Options','nosniff');h.set('Referrer-Policy','same-origin');h.set('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");return new Response(r.body,{status:r.status,headers:h});}
 if(!env.DB)return json({error:'DB_NOT_CONFIGURED'},503);const owner=id.owner;
 if(url.pathname==='/api/state'&&request.method==='GET'){const row=await env.DB.prepare('SELECT version,state,updated_at FROM plans WHERE owner=?').bind(owner).first();return json(row?{version:row.version,state:JSON.parse(row.state),updatedAt:row.updated_at}:{version:0,state:null,updatedAt:null});}
 if(url.pathname==='/api/state'&&request.method==='PUT'){
  if(request.headers.get('Origin')!==url.origin)return json({error:'ORIGIN_MISMATCH'},403);
  if(!request.headers.get('Content-Type')?.startsWith('application/json'))return json({error:'JSON_REQUIRED'},415);
  if(Number(request.headers.get('Content-Length')||0)>300000)return json({error:'TOO_LARGE'},413);
  const body=await request.text();if(body.length>300000)return json({error:'TOO_LARGE'},413);let v;try{v=JSON.parse(body);}catch{return json({error:'INVALID_JSON'},400);}
  if(!Number.isInteger(v.baseVersion)||v.baseVersion<0||v.baseVersion>1e9)return json({error:'VERSION_REQUIRED'},400);let errors;try{errors=validate(v.state)}catch{errors=['Malformed state']}if(errors.length)return json({error:'INVALID_STATE',errors},422);
  const state=JSON.stringify(v.state),next=v.baseVersion+1,at=new Date().toISOString();
  // Atomic SQLite transaction: optimistic update and history snapshot. Failed CAS writes no history.
  const write=v.baseVersion===0?env.DB.prepare('INSERT INTO plans(owner,version,state,updated_at) VALUES(?,?,?,?) ON CONFLICT(owner) DO NOTHING').bind(owner,next,state,at):env.DB.prepare('UPDATE plans SET version=?,state=?,updated_at=? WHERE owner=? AND version=?').bind(next,state,at,owner,v.baseVersion);
  const history=env.DB.prepare('INSERT OR IGNORE INTO history(owner,version,state,updated_at) SELECT owner,version,state,updated_at FROM plans WHERE owner=? AND version=? AND state=? AND updated_at=?').bind(owner,next,state,at);
  const result=await env.DB.batch([write,history]);if(result[0].meta.changes!==1){const current=await env.DB.prepare('SELECT version,updated_at FROM plans WHERE owner=?').bind(owner).first();return json({error:'CONFLICT',version:current?.version||0,updatedAt:current?.updated_at||null},409);}return json({version:next,updatedAt:at});
 }
 if(url.pathname==='/api/history'&&request.method==='GET'){const r=await env.DB.prepare('SELECT version,updated_at FROM history WHERE owner=? ORDER BY version DESC LIMIT 30').bind(owner).all();return json({history:r.results||[]});}
 const match=url.pathname.match(/^\/api\/history\/(\d+)$/);if(match&&request.method==='GET'){const r=await env.DB.prepare('SELECT version,state,updated_at FROM history WHERE owner=? AND version=?').bind(owner,+match[1]).first();return r?json({version:r.version,state:JSON.parse(r.state),updatedAt:r.updated_at}):json({error:'NOT_FOUND'},404);}
 return json({error:'NOT_FOUND'},404);
}};
