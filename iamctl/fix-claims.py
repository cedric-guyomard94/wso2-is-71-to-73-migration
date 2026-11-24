#!/usr/bin/env python3
"""Unique retouche nécessaire entre exportAll (7.1) et importAll (7.3) : le dialecte des claims locales.

7.3 refuse toute mise à jour du type de données / du caractère multi-valué des claims système,
et le fichier 7.1 ne porte pas ces champs. On ne garde donc que les claims custom (IAMCTL ne supprime
pas ce qui manque) et on convertit leur propriété 7.1 'multiValued' en champ 7.3.

usage: python3 fix-claims.py <dossier d'export>     (requiert PyYAML : pip install pyyaml)
"""
import os, sys
import yaml

p = os.path.join(sys.argv[1], "Claims", "http_wso2_org_claims.yml")
d = yaml.safe_load(open(p, encoding="utf-8"))
is_sys = lambda c: any(x.get("key") == "isSystemClaim" and str(x.get("value")) == "true" for x in c.get("properties") or [])
custom = [c for c in d["claims"] if not is_sys(c)]
for c in custom:
    mv = [x for x in c.get("properties") or [] if x.get("key") == "multiValued"]
    if mv:
        c["multiValued"] = str(mv[0]["value"]).lower() == "true"
        c["properties"] = [x for x in c["properties"] if x.get("key") != "multiValued"]
d["claims"] = custom
yaml.safe_dump(d, open(p, "w", encoding="utf-8"), sort_keys=False, allow_unicode=True, width=10_000)
print(f"{len(custom)} claim(s) custom conservée(s) : {', '.join(c['claimURI'].rsplit('/', 1)[-1] for c in custom)}")
