#!/usr/bin/env python3
"""Regenerate case.json for the public demo from the main repo's SYNTHETIC sample.

This lives in the standalone demo repo, so it needs the path to a checkout of the
main tool repo (which has afa/ and examples/). Pass it as an argument or set
AFA_REPO; defaults to a sibling clone named Air-Gapped-Forensic-Analyst.

    python generate_case.py C:\\path\\to\\Air-Gapped-Forensic-Analyst
    # or:  set AFA_REPO=...  then  python generate_case.py

Uses only the synthetic example collection — no real evidence, no model.
"""
import json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT = os.path.join(os.path.dirname(HERE), "Air-Gapped-Forensic-Analyst")
ROOT = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("AFA_REPO", DEFAULT)
if not os.path.isdir(os.path.join(ROOT, "afa")):
    sys.exit(f"Main repo not found at {ROOT!r}. Pass its path: python generate_case.py <path-to-Air-Gapped-Forensic-Analyst>")
sys.path.insert(0, ROOT)
from afa.package import load_package, verify_package
from afa.brief import build_brief, render_brief
from afa.rootcause import build_reconstruction
from afa.tools import (browser_history, filesystem_timeline, list_autoruns, map_attack,
                       scheduled_tasks, timeline, prefetch_execution, shimcache_entries, wmi_persistence)
from afa.providers import get_provider

SAMPLE = os.path.join(ROOT, "examples", "sample-collection")
ev, manifest = load_package(SAMPLE)
autoruns = list_autoruns(ev)

case = {
    "host": ev.host, "manifest": manifest, "custody": verify_package(SAMPLE),
    "summary": render_brief(build_brief(ev)),
    "rootcause": build_reconstruction(ev), "attack": map_attack(ev),
    "counts": {"events": len(ev.events), "registry": len(ev.registry),
               "processes": len(ev.processes), "network": len(ev.network),
               "users": len(ev.users), "programs": len(ev.programs),
               "prefetch": len(ev.prefetch), "shimcache": len(ev.shimcache),
               "filesystem": len(ev.filesystem), "browser": len(ev.browser), "wmi": len(ev.wmi)},
    "artifacts": {
        "processes": ev.processes, "network": ev.network, "users": ev.users,
        "programs": ev.programs, "services": ev.services,
        "persistence": autoruns["items"], "tasks": scheduled_tasks(ev)["items"],
        "events": timeline(ev)["items"], "prefetch": prefetch_execution(ev)["items"],
        "shimcache": shimcache_entries(ev)["items"], "filesystem": filesystem_timeline(ev)["items"],
        "browser": browser_history(ev)["items"], "wmi": wmi_persistence(ev)["items"]},
}

planner = get_provider("offline")
INTENTS = [
    ("map_attack", ["mitre","att&ck","technique","ttp","tactic","kill chain"], "Map this incident to MITRE ATT&CK."),
    ("wmi", ["wmi","subscription","event consumer","event filter","consumerbinding"], "Is there WMI subscription persistence?"),
    ("process_tree", ["process tree","process chain","parent process","spawn","what spawned"], "What spawned the malicious process?"),
    ("scheduled", ["scheduled task","schtask","scheduled"], "Are there malicious scheduled tasks?"),
    ("accounts", ["account","new user","user creat"], "Were any new user accounts created?"),
    ("persistence", ["persist","autorun","run key","startup","stay","reboot","service"], "How did the attacker establish persistence?"),
    ("usb", ["usb","removable","thumb","external device","exfil"], "Any USB or removable-device activity?"),
    ("antiforensics", ["cover","anti forensic","antiforensic","clear","wipe","tamper","track"], "Did the attacker clear logs or cover their tracks?"),
    ("powershell", ["scriptblock","script block","4104","decoded","powershell command"], "Show decoded PowerShell scriptblock activity."),
    ("prefetch", ["prefetch","run count","how many times","times executed"], "What does prefetch show about execution?"),
    ("shimcache", ["shimcache","appcompat","amcache present"], "What's in the shimcache?"),
    ("filesystem", ["mft","file system","filesystem","first write","first written","dropped","when was","written to disk","file timeline"], "When were malicious files first written to disk?"),
    ("browser", ["browser","download","chrome","edge","firefox","drive by","drive-by","url visited","downloaded"], "Was anything downloaded via the browser?"),
    ("programs", ["amcache","shimcache","program execution","what ran","programs"], "What programs ran?"),
    ("network", ["c2","command and control","beacon","outbound","network","connect","external"], "Is there command-and-control activity?"),
    ("timeline", ["timeline","sequence","order","what happened","chronolog"], "Build a timeline of the compromise."),
    ("process", ["process","executed","powershell","malware","suspicious","ran"], "What suspicious processes executed?"),
    ("default", [], "Give me a triage summary of this host."),
]
intents = []
for iid, kws, q in INTENTS:
    ans = planner.investigate(q, ev)
    intents.append({"id": iid, "keywords": kws, "example": q,
                    "text": ans.text, "tool_calls": [{"name": c.name} for c in ans.tool_calls]})

io = case["rootcause"]["iocs"]
indicators = {}
for ip in io.get("c2", []) + io.get("external_ips", []):
    ans = planner.investigate(f"What evidence connects to {ip}?", ev)
    indicators[ip.split(":")[0]] = {"text": ans.text, "tool_calls": [{"name": c.name} for c in ans.tool_calls]}

case["demo_qa"] = {"intents": intents, "indicators": indicators,
                   "suggested": ["How did the attacker establish persistence?","Is there command-and-control activity?",
                                 "Map this incident to MITRE ATT&CK.","What programs ran?","Build a timeline of the compromise."]}

out = os.path.join(HERE, "case.json")
with open(out, "w", encoding="utf-8") as f:
    json.dump(case, f, indent=2)
print(f"wrote {out}  ({os.path.getsize(out)} bytes, {len(intents)} intents, indicators={list(indicators)})")
