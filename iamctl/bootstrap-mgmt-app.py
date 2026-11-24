#!/usr/bin/env python3
"""Crée (idempotent) l'application M2M utilisée par IAMCTL et prépare configs/<env>/ :
serverConfig.json (client_id / secret de l'app), toolConfig.json et keywordConfig.json.

usage: bootstrap-mgmt-app.py <base_url> <env_dir> <server_version> [app_name]
       ex. ./bootstrap-mgmt-app.py https://is71.example:9443 configs/is71 7.1.0
Auth : basic. Utilisateur et mot de passe demandés à l'exécution (ou IS_USER / IS_PASSWORD).
"""
import json, os, shutil, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "lib"))
from islib import IS, credentials, log

if len(sys.argv) < 4:
    sys.exit(__doc__)
base, env_dir, version = sys.argv[1:4]
app_name = sys.argv[4] if len(sys.argv) > 4 else "iamctl-mgmt"
s = IS(base, *credentials(base))
s.wait_up()

apps = s.get(f"/api/server/v1/applications?filter=name+eq+{app_name}")["applications"]
if apps:
    app_id = apps[0]["id"]
    log(f"[{base}] app {app_name} existe déjà ({app_id})")
else:
    s.post("/api/server/v1/applications", {
        "name": app_name,
        "description": "Application de management IAMCTL (client_credentials)",
        "templateId": "m2m-application",
        "inboundProtocolConfiguration": {"oidc": {"grantTypes": ["client_credentials"], "publicClient": False}},
    })
    app_id = s.get(f"/api/server/v1/applications?filter=name+eq+{app_name}")["applications"][0]["id"]
    log(f"[{base}] app {app_name} créée ({app_id})")

# Autorise toutes les API de management (scopes complets)
already = {a["id"] for a in s.get(f"/api/server/v1/applications/{app_id}/authorized-apis")}
n = 0
for r in s.get("/api/server/v1/api-resources?limit=500")["apiResources"]:
    if r["type"] not in ("TENANT", "SYSTEM", "ORGANIZATION") or r["id"] in already:
        continue
    scopes = [x["name"] for x in s.get(f"/api/server/v1/api-resources/{r['id']}").get("scopes", [])]
    out = s.try_("POST", f"/api/server/v1/applications/{app_id}/authorized-apis",
                 {"id": r["id"], "policyIdentifier": "RBAC", "scopes": scopes})
    if "_error" in out:
        log(f"  ! {r['name']}: {out['_error'][:160]}")
    else:
        n += 1
log(f"[{base}] {n} API autorisées en plus ({len(already)} déjà)")

oidc = s.get(f"/api/server/v1/applications/{app_id}/inbound-protocols/oidc")
os.makedirs(env_dir, exist_ok=True)
with open(os.path.join(env_dir, "serverConfig.json"), "w") as f:
    json.dump({"SERVER_URL": base, "CLIENT_ID": oidc["clientId"], "CLIENT_SECRET": oidc["clientSecret"],
               "TENANT_DOMAIN": "carbon.super", "SERVER_VERSION": version}, f, indent=2)
for f in ("toolConfig.json", "keywordConfig.json"):
    shutil.copy(os.path.join(HERE, f), os.path.join(env_dir, f))
log(f"-> {env_dir}/ (serverConfig.json contient le secret de l'app)")
