#!/usr/bin/env python3
"""CloudSec Checklist: offline review of a provider-neutral JSON configuration snapshot."""
import argparse, json
from pathlib import Path

RULES = [
 ("public_storage","storage","public_access",False,"high","Storage should not allow public access unless explicitly required."),
 ("audit_logging","logging","enabled",True,"medium","Enable and retain audit logs for security investigations."),
 ("mfa_required","identity","mfa_required",True,"high","Require MFA for privileged and interactive identities."),
 ("encryption_at_rest","encryption","at_rest",True,"high","Enable encryption at rest for stored data."),
 ("encryption_in_transit","encryption","in_transit",True,"high","Require TLS for data in transit."),
 ("least_privilege","identity","least_privilege",True,"medium","Use narrowly scoped roles and permissions."),
 ("backup_enabled","backup","enabled",True,"medium","Maintain tested backups with appropriate access controls.")
]
def evaluate(snapshot):
    findings=[]
    for rule,section,key,expected,severity,advice in RULES:
        value=snapshot.get(section,{}).get(key,None)
        if value is None: status="unknown"
        elif value==expected: status="pass"
        else: status="review"
        findings.append({"id":rule,"status":status,"severity":severity,"observed":value,"recommendation":advice})
    counts={s:sum(x["status"]==s for x in findings) for s in ("pass","review","unknown")}
    return {"checks":len(findings),"summary":counts,"findings":findings,
            "scope":"Offline checklist against a user-supplied JSON snapshot; no cloud APIs are called."}
def main():
    p=argparse.ArgumentParser(description="Review a sanitized cloud configuration JSON snapshot.")
    p.add_argument("snapshot",type=Path); p.add_argument("--output",type=Path)
    a=p.parse_args()
    try: data=json.loads(a.snapshot.read_text(encoding="utf-8"))
    except (OSError,json.JSONDecodeError) as e: p.error(str(e))
    if not isinstance(data,dict): p.error("Top-level JSON value must be an object.")
    result=evaluate(data); text=json.dumps(result,indent=2,ensure_ascii=False)
    if a.output: a.output.write_text(text+"\n",encoding="utf-8")
    print(text)
if __name__=="__main__": main()
