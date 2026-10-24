"""Checks that every nuclei event is in a raijin-scan result.

An event is its (template-id[:matcher-name], matched-at) pair. It must be in a finding's locations,
or in a group whose variants and locations contain it.

usage: python verify.py <nuclei.jsonl> <raijin.json>
"""
import json,sys
raw,out=sys.argv[1],sys.argv[2]
o=json.load(open(out))
pairs=set()
for f in o["findings"]:
    for l in f["locations"]: pairs.add((f["id"],l.split(" [")[0]))
for g in o["groups"]:
    for v in (g.get("variants") or [""]):
        for l in g.get("locations",[]): pairs.add((g["id"]+(":"+v if v else ""),l))
miss=[]; n=0
for line in open(raw):
    e=json.loads(line); n+=1
    k=e["template-id"]+(":"+e["matcher-name"] if e.get("matcher-name") else "")
    if (k,e["matched-at"]) not in pairs: miss.append((k,e["matched-at"]))
print(f"{n} nuclei events, {len(set(miss))} (finding, location) pairs missing from output", "truncated" if o.get("budget") else "")
for m in sorted(set(miss))[:5]: print("  MISSING",m)
