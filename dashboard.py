"""
Local web dashboard for the AI vulnerability scanner.
Run: python dashboard.py   then open http://127.0.0.1:8765
Uses only the Python standard library plus the project's own modules.
Scan ONLY targets you own or have written permission to test.
"""
import asyncio
import json
import secrets
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

import scanner
from report import KB, DEFAULT, SEV_ORDER
from sigma_gen import RULES, safe_name

HOST, PORT = "127.0.0.1", 8765
NONCE = secrets.token_urlsafe(16)
JOBS = {}
BUSY = threading.Semaphore(1)  # one scan at a time


def enrich(f):
    owasp, cwe, why, fix = KB.get(f["id"], DEFAULT)
    item = dict(f)
    item.update(owasp=owasp, cwe=cwe, why=why, fix=fix,
                rule=("rules/" + safe_name(f["id"])) if f["id"] in RULES else None)
    return item


def sort_findings(items):
    return sorted(items, key=lambda f: SEV_ORDER.get(f["severity"], 9))


def compare(before, after):
    b = {f["id"]: f for f in before}
    a = {f["id"]: f for f in after}
    brief = lambda f: {"title": f["title"], "severity": f["severity"]}
    return {
        "before": len(b),
        "fixed": [brief(b[i]) for i in b if i not in a],
        "open": [brief(a[i]) for i in a if i in b],
        "new": [brief(a[i]) for i in a if i not in b],
    }


def run_job(job_id, url, nuclei, compare_to):
    job = JOBS[job_id]
    try:
        job["stage"] = "Quick scan"
        quick = asyncio.run(scanner.quick_scan(url))
        job["findings"] = sort_findings([enrich(f) for f in quick])
        if nuclei:
            job["stage"] = "Deep scan (Nuclei), first results already shown"
            deep = asyncio.run(scanner.run_nuclei(url, timeout=300))
            job["findings"] = sort_findings([enrich(f) for f in quick + deep])
        if compare_to in JOBS:
            job["verification"] = compare(JOBS[compare_to]["findings"], job["findings"])
        job["status"], job["stage"] = "done", "Finished"
    except Exception as e:
        job["status"] = "error"
        job["error"] = f"Scan failed ({type(e).__name__}). Is the target reachable?"
    finally:
        BUSY.release()


def run_ai(job_id):
    job = JOBS[job_id]
    job["ai"] = {"status": "running", "text": ""}
    try:
        from ai_analyze import analyze
        plain = [{k: f[k] for k in ("id", "title", "severity", "evidence", "location")}
                 for f in job["findings"]]
        job["ai"] = {"status": "done", "text": analyze(plain, job["url"])}
    except (Exception, SystemExit) as e:
        job["ai"] = {"status": "error",
                     "text": str(e) or "AI is not available. Install Ollama or set ANTHROPIC_API_KEY."}


PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AI Vulnerability Scanner</title>
<style nonce="__NONCE__">
:root{--bg:#f6f7f9;--card:#fff;--text:#1b1f24;--muted:#5b6570;--line:#dde1e6;--accent:#2457d6;
--critical:#8b0000;--high:#c62828;--medium:#c77700;--low:#2e7d32;--info:#546e7a}
@media (prefers-color-scheme:dark){:root{--bg:#14171a;--card:#1d2125;--text:#e8eaed;--muted:#9aa4af;--line:#2d333a;--accent:#6c97ff;
--critical:#ff6b6b;--high:#ff7a7a;--medium:#ffb04a;--low:#6fcf7a;--info:#90a4ae}}
*{box-sizing:border-box}body{margin:0;font:15px/1.5 system-ui,sans-serif;background:var(--bg);color:var(--text)}
main{max-width:900px;margin:0 auto;padding:24px 16px 60px}
h1{font-size:22px;margin:0 0 4px}.sub{color:var(--muted);margin:0 0 20px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;margin-bottom:14px}
input[type=text]{width:100%;padding:10px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--text);font-size:15px}
label{display:block;margin:8px 0;color:var(--muted);font-size:14px}
button{padding:9px 16px;border:0;border-radius:8px;background:var(--accent);color:#fff;font-size:14px;cursor:pointer;margin:6px 8px 0 0}
button.alt{background:transparent;color:var(--accent);border:1px solid var(--accent)}
button:disabled{opacity:.5;cursor:default}
#msg{color:var(--high);margin-top:8px}.stage{color:var(--muted)}
.sum{display:flex;gap:10px;flex-wrap:wrap}.pill{padding:6px 12px;border-radius:20px;border:1px solid var(--line);font-size:13px}
.badge{display:inline-block;padding:2px 9px;border-radius:12px;font-size:12px;font-weight:600;color:#fff;margin-right:8px;text-transform:uppercase}
.sev-critical{background:var(--critical)}.sev-high{background:var(--high)}.sev-medium{background:var(--medium)}
.sev-low{background:var(--low)}.sev-info{background:var(--info)}
details{border:1px solid var(--line);border-radius:8px;margin:8px 0;background:var(--card)}
summary{padding:10px 12px;cursor:pointer}.body{padding:0 14px 12px}
.meta{color:var(--muted);font-size:13px}pre{background:var(--bg);padding:10px;border-radius:6px;overflow-x:auto;white-space:pre-wrap;font-size:13px}
.ver div{margin:2px 0}.hidden{display:none}
</style></head><body><main>
<h1>AI Vulnerability Scanner</h1>
<p class="sub">Enter a site you own, see the weaknesses, get fixes, then re-scan to prove they worked.</p>
<div class="card">
 <input id="url" type="text" placeholder="http://localhost:3000" value="http://localhost:3000">
 <label><input id="confirm" type="checkbox"> I own this target or have written permission to test it</label>
 <label><input id="nuclei" type="checkbox"> Also run the deep scan (Nuclei, slower)</label>
 <button id="go">Scan</button><span class="stage" id="stage"></span>
 <div id="msg"></div>
</div>
<div id="result" class="hidden">
 <div class="card"><div class="sum" id="sum"></div>
  <div style="margin-top:8px">
   <button id="rescan" class="alt">Re-scan and verify fixes</button>
   <button id="dl" class="alt">Download report</button>
   <button id="ai" class="alt">AI explanation</button>
  </div></div>
 <div class="card hidden ver" id="ver"></div>
 <div class="card hidden" id="aibox"><strong>AI explanation</strong><pre id="aitext"></pre></div>
 <div id="list"></div>
</div>
</main>
<script nonce="__NONCE__">
const $ = id => document.getElementById(id);
let jobId = null, timer = null, job = null, sig = "";
function el(tag, cls, text){const e=document.createElement(tag);if(cls)e.className=cls;if(text!==undefined)e.textContent=text;return e;}
function setMsg(t){$("msg").textContent=t;}
async function post(path, body){
  const r = await fetch(path,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body||{})});
  let data = {}; try{data = await r.json();}catch(e){}
  return {ok:r.ok, data};
}
async function start(compareTo){
  setMsg("");
  const res = await post("/api/scan",{url:$("url").value.trim(),confirm:$("confirm").checked,
    nuclei:$("nuclei").checked,compare_to:compareTo||null});
  if(!res.ok){setMsg(res.data.error||"Request failed");return;}
  jobId = res.data.id; sig = ""; $("go").disabled = true;
  if(timer) clearInterval(timer);
  timer = setInterval(poll,1500); poll();
}
async function poll(){
  const r = await fetch("/api/scan/"+jobId); if(!r.ok) return;
  job = await r.json();
  const aiBusy = job.ai && job.ai.status==="running";
  const s = JSON.stringify([job.status,job.stage,job.findings.length,!!job.verification,job.ai&&job.ai.status]);
  if(s!==sig){sig=s;render();}
  if(job.status!=="running" && !aiBusy){clearInterval(timer);timer=null;$("go").disabled=false;}
}
function render(){
  $("stage").textContent = job.status==="running" ? " "+job.stage+"..." : "";
  if(job.status==="error"){setMsg(job.error);$("go").disabled=false;}
  $("result").classList.toggle("hidden", job.findings.length===0 && job.status!=="done");
  const counts = {};
  job.findings.forEach(f=>counts[f.severity]=(counts[f.severity]||0)+1);
  const sum=$("sum"); sum.textContent="";
  sum.appendChild(el("span","pill",job.findings.length+" findings"));
  ["critical","high","medium","low","info"].forEach(k=>{if(counts[k])sum.appendChild(el("span","pill",counts[k]+" "+k));});
  const done = job.status==="done";
  $("rescan").disabled=!done; $("dl").disabled=!done; $("ai").disabled=!done || (job.ai&&job.ai.status==="running");
  const list=$("list"); list.textContent="";
  job.findings.forEach(f=>{
    const d=el("details"); const s=el("summary");
    s.appendChild(el("span","badge sev-"+f.severity,f.severity)); s.appendChild(document.createTextNode(f.title));
    d.appendChild(s); const b=el("div","body");
    b.appendChild(el("div","meta",f.owasp+"  |  "+f.cwe+"  |  "+f.location));
    b.appendChild(el("p",null,f.why));
    b.appendChild(el("strong",null,"Fix")); b.appendChild(el("pre",null,f.fix));
    b.appendChild(el("div","meta","Evidence: "+f.evidence));
    b.appendChild(el("div","meta",f.rule?("Detection rule: "+f.rule):"Detection: no log-based rule (configuration finding)"));
    d.appendChild(b); list.appendChild(d);
  });
  const ver=$("ver"); ver.textContent="";
  if(job.verification){
    ver.classList.remove("hidden"); const v=job.verification;
    ver.appendChild(el("strong",null,"Fix verification: "+v.fixed.length+" of "+v.before+" findings confirmed fixed"));
    [["Fixed",v.fixed],["Still open",v.open],["New after fix",v.new]].forEach(([t,items])=>{
      const box=el("div"); box.appendChild(el("div","meta",t));
      if(!items.length) box.appendChild(el("div",null,"none"));
      items.forEach(i=>box.appendChild(el("div",null,"["+i.severity+"] "+i.title)));
      ver.appendChild(box);});
  } else ver.classList.add("hidden");
  if(job.ai){$("aibox").classList.remove("hidden");
    $("aitext").textContent = job.ai.status==="running"?"Working, this can take a few minutes...":job.ai.text;}
}
function report(){
  const L=["# Security Assessment Report","","Target: "+job.url,"Findings: "+job.findings.length,""];
  job.findings.forEach(f=>{L.push("## ["+f.severity.toUpperCase()+"] "+f.title,"","- "+f.owasp+" | "+f.cwe,
    "- Location: "+f.location,"- Evidence: "+f.evidence,"","What it means: "+f.why,"","Fix:","","    "+f.fix.split("\\n").join("\\n    "),"");});
  if(job.verification){const v=job.verification;L.push("## Fix verification","",v.fixed.length+" of "+v.before+" fixed","");}
  const blob=new Blob([L.join("\\n")],{type:"text/markdown"});
  const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download="security_report.md";a.click();
}
$("go").addEventListener("click",()=>start(null));
$("rescan").addEventListener("click",()=>start(jobId));
$("dl").addEventListener("click",report);
$("ai").addEventListener("click",async()=>{const r=await post("/api/scan/"+jobId+"/ai");
  if(!r.ok){setMsg(r.data.error||"Request failed");return;}
  if(!timer) timer=setInterval(poll,1500); poll();});
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def version_string(self):
        return "dashboard"  # do not reveal Python/server versions

    def send_json(self, code, obj):
        self.send_bytes(code, json.dumps(obj).encode(), "application/json")

    def send_bytes(self, code, data, ctype):
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         f"default-src 'none'; connect-src 'self'; "
                         f"script-src 'nonce-{NONCE}'; style-src 'nonce-{NONCE}'")
        self.end_headers()
        self.wfile.write(data)

    def host_ok(self):
        # Blocks DNS-rebinding: only accept our own host name
        return self.headers.get("Host") in (f"{HOST}:{PORT}", f"localhost:{PORT}")

    def do_GET(self):
        if not self.host_ok():
            return self.send_json(403, {"error": "Bad host"})
        if self.path == "/":
            return self.send_bytes(200, PAGE.replace("__NONCE__", NONCE).encode(), "text/html")
        parts = self.path.strip("/").split("/")
        if len(parts) == 3 and parts[:2] == ["api", "scan"] and parts[2] in JOBS:
            return self.send_json(200, JOBS[parts[2]])
        self.send_json(404, {"error": "Not found"})

    def read_json(self):
        # Requiring JSON blocks cross-site form posts (CSRF) from other web pages
        if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
            self.send_json(415, {"error": "Use application/json"})
            return None
        size = int(self.headers.get("Content-Length", 0))
        if size > 10_000:
            self.send_json(413, {"error": "Request too large"})
            return None
        try:
            return json.loads(self.rfile.read(size) or b"{}")
        except json.JSONDecodeError:
            self.send_json(400, {"error": "Bad JSON"})
            return None

    def do_POST(self):
        if not self.host_ok():
            return self.send_json(403, {"error": "Bad host"})
        body = self.read_json()
        if body is None:
            return
        parts = self.path.strip("/").split("/")

        if self.path == "/api/scan":
            url = str(body.get("url", ""))[:300]
            p = urlparse(url)
            if p.scheme not in ("http", "https") or not p.hostname:
                return self.send_json(400, {"error": "Enter a full URL, like http://localhost:3000"})
            if p.hostname not in ("localhost", "127.0.0.1") and not body.get("confirm"):
                return self.send_json(400, {"error": "Tick the box to confirm you own this target or have permission."})
            if not BUSY.acquire(blocking=False):
                return self.send_json(429, {"error": "A scan is already running. Wait for it to finish."})
            job_id = uuid.uuid4().hex[:12]
            JOBS[job_id] = {"id": job_id, "url": url, "status": "running", "stage": "Starting",
                            "findings": [], "verification": None, "error": None, "ai": None}
            threading.Thread(target=run_job, daemon=True,
                             args=(job_id, url, bool(body.get("nuclei")), body.get("compare_to"))).start()
            return self.send_json(200, {"id": job_id})

        if len(parts) == 4 and parts[:2] == ["api", "scan"] and parts[3] == "ai" and parts[2] in JOBS:
            job = JOBS[parts[2]]
            if job["status"] != "done":
                return self.send_json(400, {"error": "Wait for the scan to finish."})
            if job["ai"] and job["ai"]["status"] == "running":
                return self.send_json(429, {"error": "AI is already working."})
            threading.Thread(target=run_ai, daemon=True, args=(parts[2],)).start()
            return self.send_json(200, {"ok": True})

        self.send_json(404, {"error": "Not found"})

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    print(f"Dashboard: http://{HOST}:{PORT}  (Ctrl+C to stop)")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
