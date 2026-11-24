#!/usr/bin/env python3
"""Migration des SP, claims et connexions (IdP fédérés + trusted token issuers) WSO2 IS 7.1 -> 7.3
par les API REST de management, sans IAMCTL. Python 3 stdlib uniquement.

  ./api-migrate.py export <src_url> <bundle.json>      ne contacte que la source
  ./api-migrate.py import <bundle.json> <dst_url>      ne contacte que la cible (idempotent)

Auth : basic (IS_USER / IS_PASSWORD, défaut admin/admin). Le bundle contient des secrets (client secrets).

Périmètre : claims locales custom (+ mappings par user store), dialectes et claims externes, scopes OIDC,
API resources, IdP fédérés, trusted token issuers, applications (OIDC / SAML / M2M, client_id et secret
conservés), APIs autorisées, rôles d'application, templates e-mail spécifiques aux applications.
Les user stores ne sont pas migrés : ceux référencés par les claims doivent exister sur la cible.
"""
import base64, copy, json, os, sys, time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
from islib import IS

API = "/api/server/v1"
SYSTEM_APPS = {"Console", "My Account", "iamctl-mgmt"}
SKIP = {"id", "self", "created", "lastModified", "links"}
b64 = lambda x: base64.urlsafe_b64encode(x.encode()).decode().rstrip("=")
q = lambda x: x.replace(" ", "+")
INBOUND = {"oauth2": "oidc", "samlsso": "saml", "passivests": "passive-sts", "wstrust": "ws-trust"}


def clean(d, extra=()):
    return {k: v for k, v in d.items() if k not in SKIP and k not in extra}


def is_system_claim(c):
    return any(p["key"] == "isSystemClaim" and str(p["value"]) == "true" for p in c.get("properties", []))


# =================================================================================== EXPORT
def export(src_url, out):
    s = IS(src_url, os.environ.get("IS_USER", "admin"), os.environ.get("IS_PASSWORD", "admin"))
    b = {"source": src_url, "exported_at": time.strftime("%Y-%m-%d %H:%M:%S")}

    # --- claims
    local = s.get(f"{API}/claim-dialects/local/claims")
    b["local_claims"] = [clean(c) for c in local if not is_system_claim(c)]
    # claims système : seuls leurs mappings d'attributs par user store sont repris (ex. username -> sAMAccountName)
    b["system_claim_mappings"] = {c["claimURI"]: c.get("attributeMapping", []) for c in local if is_system_claim(c)}
    b["system_claim_excluded_us"] = {c["claimURI"]: p["value"] for c in local if is_system_claim(c)
                                     for p in c.get("properties", []) if p["key"] == "ExcludedUserStores" and p["value"]}
    b["dialects"] = {}
    for d in s.get(f"{API}/claim-dialects"):
        if d["dialectURI"] == "http://wso2.org/claims":
            continue
        b["dialects"][d["dialectURI"]] = [{"claimURI": c["claimURI"], "mappedLocalClaimURI": c["mappedLocalClaimURI"]}
                                          for c in s.get(f"{API}/claim-dialects/{d['id']}/claims")]
    b["oidc_scopes"] = s.get(f"{API}/oidc/scopes")

    # --- API resources (métier)
    b["api_resources"] = []
    for r in s.get(f"{API}/api-resources?limit=500")["apiResources"]:
        if r["type"] == "BUSINESS":
            r = clean(s.get(f"{API}/api-resources/{r['id']}"), ("type", "properties"))
            r["scopes"] = [clean(x) for x in r.get("scopes", [])]  # 'id' de scope refusé en POST
            b["api_resources"].append(r)

    # --- IdP fédérés et trusted token issuers
    b["idps"] = []
    for i in s.get(f"{API}/identity-providers?limit=500").get("identityProviders", []):
        d = s.get(f"{API}/identity-providers/{i['id']}")
        fa = d.get("federatedAuthenticators") or {}
        auths = []
        for a in fa.get("authenticators", []):
            full = s.get(f"{API}/identity-providers/{i['id']}/federated-authenticators/{a['authenticatorId']}")
            auths.append({k: full[k] for k in ("authenticatorId", "isEnabled", "isDefault", "properties") if k in full})
        d["federatedAuthenticators"] = {"defaultAuthenticatorId": fa.get("defaultAuthenticatorId", ""), "authenticators": auths}
        d["provisioning"] = {"jit": s.get(f"{API}/identity-providers/{i['id']}/provisioning/jit")}
        b["idps"].append(clean(d))

    # --- applications
    b["apps"] = []
    for a in s.get(f"{API}/applications?limit=500")["applications"]:
        if a["name"] in SYSTEM_APPS:
            continue
        d = s.get(f"{API}/applications/{a['id']}")
        inbound = {}
        for p in d.get("inboundProtocols", []) or []:
            t = INBOUND.get(p["type"], p["type"])
            inbound[t] = s.get(f"{API}/applications/{a['id']}/inbound-protocols/{t}")
        authz = [{"identifier": x["identifier"], "policyIdentifier": x.get("policyId", "RBAC"),
                  "scopes": [sc["name"] for sc in x.get("authorizedScopes", [])]}
                 for x in s.get(f"{API}/applications/{a['id']}/authorized-apis")]
        b["apps"].append({"app": clean(d, ("inboundProtocols", "clientId", "issuer", "access", "applicationVersion", "realm")),
                          "inbound": inbound, "authorized_apis": authz, "_src_id": a["id"]})

    # --- rôles d'application
    names = {x["_src_id"]: x["app"]["name"] for x in b["apps"]}
    b["app_roles"] = []
    for r in s.get("/scim2/v2/Roles?count=1000").get("Resources", []):
        full = s.get(f"/scim2/v2/Roles/{r['id']}")
        aud = full.get("audience", {})
        if aud.get("type") == "application" and aud.get("value") in names:
            b["app_roles"].append({"displayName": full["displayName"], "app": names[aud["value"]],
                                   "permissions": [p["value"] for p in full.get("permissions", [])]})

    # --- templates e-mail spécifiques aux applications
    b["app_email_templates"] = []
    for t in s.get(f"{API}/notification/email/template-types"):
        for x in b["apps"]:
            lst = s.try_("GET", f"{API}/notification/email/template-types/{t['id']}/app-templates/{x['_src_id']}")
            for loc in lst if isinstance(lst, list) else []:
                tpl = s.get(f"{API}/notification/email/template-types/{t['id']}/app-templates/{x['_src_id']}/{loc['locale']}")
                b["app_email_templates"].append({"type": t["displayName"], "app": x["app"]["name"], "template": tpl})

    json.dump(b, open(out, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
    print(f"export {src_url} -> {out}\n  claims locales custom {len(b['local_claims'])}, dialectes {len(b['dialects'])}, "
          f"scopes {len(b['oidc_scopes'])}, API {len(b['api_resources'])}, IdP {len(b['idps'])} "
          f"(dont TTI {sum(1 for i in b['idps'] if i.get('templateId') == 'trusted-token-issuer')}), "
          f"apps {len(b['apps'])}, rôles d'app {len(b['app_roles'])}, templates d'app {len(b['app_email_templates'])}")


# =================================================================================== IMPORT
class Import:
    def __init__(self, bundle, dst_url):
        self.b = json.load(open(bundle, encoding="utf-8"))
        self.s = IS(dst_url, os.environ.get("IS_USER", "admin"), os.environ.get("IS_PASSWORD", "admin"))
        self.stats, self.errors, self.warnings = {}, [], []

    def ok(self, kind, action):
        self.stats.setdefault(kind, {}).setdefault(action, 0)
        self.stats[kind][action] += 1

    def run(self, kind, label, fn):
        try:
            fn()
        except RuntimeError as e:
            self.errors.append(f"{kind} {label}: {e}")
            print(f"  ✘ {kind} {label}: {str(e)[:300]}")

    # ---------------------------------------------------------------- pré-requis
    def prerequisites(self):
        have = {u["name"] for u in self.s.get(f"{API}/userstores")}
        need = {m["userstore"] for c in self.b["local_claims"] for m in c.get("attributeMapping", [])
                if m["userstore"].upper() != "PRIMARY"}
        need |= {m["userstore"] for ms in self.b.get("system_claim_mappings", {}).values() for m in ms
                 if m["userstore"].upper() != "PRIMARY"}
        miss = sorted(need - have)
        if miss:
            raise SystemExit(f"user store(s) absent(s) de la cible : {miss} -> lancez d'abord le playbook Ansible")

    # ---------------------------------------------------------------- claims
    def claims(self):
        s = self.s
        cur = {c["claimURI"]: c for c in s.get(f"{API}/claim-dialects/local/claims")}
        for c in self.b["local_claims"]:
            body = copy.deepcopy(c)
            body.pop("dialectURI", None)
            mv = [p for p in body.get("properties", []) if p["key"] == "multiValued"]  # 7.1 -> 7.3
            if mv:
                body["multiValued"] = str(mv[0]["value"]).lower() == "true"
                body["properties"] = [p for p in body["properties"] if p["key"] != "multiValued"]
            uri = c["claimURI"]
            if uri not in cur:
                self.run("claim", uri, lambda: (s.post(f"{API}/claim-dialects/local/claims", body), self.ok("claims locales", "créée")))
            else:
                self.run("claim", uri, lambda: (s.put(f"{API}/claim-dialects/local/claims/{b64(uri)}", body), self.ok("claims locales", "mise à jour")))
        # mappings des claims système : la claim 7.3 est conservée, seuls les attributs par user store sont alignés
        for uri, src_maps in self.b.get("system_claim_mappings", {}).items():
            t = cur.get(uri)
            if t is None:
                self.warnings.append(f"claim système {uri} absente de la 7.3 (mapping non repris)")
                continue
            want = {m["userstore"].upper(): m for m in t.get("attributeMapping", [])}
            want.update({m["userstore"].upper(): m for m in src_maps})
            new = sorted(want.values(), key=lambda m: m["userstore"])
            excl = self.b.get("system_claim_excluded_us", {}).get(uri)  # user stores exclus de la claim
            t_excl = next((p["value"] for p in t.get("properties", []) if p["key"] == "ExcludedUserStores"), "")
            if new != sorted(t.get("attributeMapping", []), key=lambda m: m["userstore"]) or (excl and excl != t_excl):
                body = {k: v for k, v in t.items() if k not in ("id", "dialectURI")}
                body["attributeMapping"] = new
                if excl:
                    body["properties"] = [p for p in body.get("properties", []) if p["key"] != "ExcludedUserStores"] + \
                                         [{"key": "ExcludedUserStores", "value": excl}]
                self.run("mapping", uri, lambda: (s.put(f"{API}/claim-dialects/local/claims/{b64(uri)}", body),
                                                  self.ok("mappings claims système", "aligné")))
        custom_local = {c["claimURI"] for c in self.b["local_claims"]}
        dialects = {d["dialectURI"] for d in s.get(f"{API}/claim-dialects")}
        for uri, claims in self.b["dialects"].items():
            if uri not in dialects:
                self.run("dialecte", uri, lambda: (s.post(f"{API}/claim-dialects", {"dialectURI": uri}), self.ok("dialectes", "créé")))
            tgt = {c["claimURI"]: c for c in s.get(f"{API}/claim-dialects/{b64(uri)}/claims")}
            for c in claims:
                t = tgt.get(c["claimURI"])
                if t is None:
                    self.run("claim externe", c["claimURI"], lambda: (s.post(f"{API}/claim-dialects/{b64(uri)}/claims", c),
                                                                      self.ok("claims externes", "créée")))
                elif t["mappedLocalClaimURI"] != c["mappedLocalClaimURI"]:
                    if c["mappedLocalClaimURI"] in custom_local:
                        self.run("claim externe", c["claimURI"], lambda: (s.put(f"{API}/claim-dialects/{b64(uri)}/claims/{t['id']}", c),
                                                                          self.ok("claims externes", "mise à jour")))
                    else:
                        self.warnings.append(f"{uri} / {c['claimURI']} : mapping 7.1 {c['mappedLocalClaimURI']} != 7.3 "
                                             f"{t['mappedLocalClaimURI']} (claim système, 7.3 conservé)")

    def scopes(self):
        s = self.s
        cur = {x["name"]: x for x in s.get(f"{API}/oidc/scopes")}
        for sc in self.b["oidc_scopes"]:
            t = cur.get(sc["name"])
            if t is None:
                self.run("scope", sc["name"], lambda: (s.post(f"{API}/oidc/scopes", sc), self.ok("scopes OIDC", "créé")))
            elif set(sc["claims"]) - set(t["claims"]) or sc.get("description") != t.get("description"):
                body = {"displayName": sc["displayName"], "description": sc.get("description", ""),
                        "claims": sorted(set(t["claims"]) | set(sc["claims"]))}  # union : on garde les ajouts 7.3
                self.run("scope", sc["name"], lambda: (s.put(f"{API}/oidc/scopes/{sc['name']}", body), self.ok("scopes OIDC", "mis à jour")))

    def api_resources(self):
        s = self.s
        self.api_ids = {}
        cur = {r["identifier"]: r for r in s.get(f"{API}/api-resources?limit=500")["apiResources"]}
        for r in self.b["api_resources"]:
            t = cur.get(r["identifier"])
            if t is None:
                self.run("API", r["identifier"], lambda: (s.post(f"{API}/api-resources", r), self.ok("API resources", "créée")))
            else:
                have = {x["name"] for x in s.get(f"{API}/api-resources/{t['id']}").get("scopes", [])}
                add = [x for x in r.get("scopes", []) if x["name"] not in have]
                if add:
                    self.run("API", r["identifier"], lambda: (s.patch(f"{API}/api-resources/{t['id']}", {"addedScopes": add}),
                                                              self.ok("API resources", "scopes ajoutés")))
        self.api_ids = {r["identifier"]: r["id"] for r in s.get(f"{API}/api-resources?limit=500")["apiResources"]}

    # ---------------------------------------------------------------- IdP / TTI
    def idps(self):
        s = self.s
        cur = {i["name"]: i for i in s.get(f"{API}/identity-providers?limit=500").get("identityProviders", [])}
        for d in self.b["idps"]:
            kind = "TTI" if d.get("templateId") == "trusted-token-issuer" else "IdP"
            body = copy.deepcopy(d)
            body.pop("groups", None)
            enabled = body.pop("isEnabled", True)  # champ en lecture seule en POST : appliqué ensuite par PATCH
            ia = body.get("implicitAssociation") or {}
            if not ia.get("isEnabled"):  # 7.3 refuse {isEnabled: false, lookupAttribute: []} renvoyé par 7.1
                body.pop("implicitAssociation", None)
            for k in ("userIdClaim", "roleClaim"):  # IdP sans mapping : 7.1 renvoie {uri: null}, refusé en 7.3
                if not ((body.get("claims") or {}).get(k) or {}).get("uri"):
                    (body.get("claims") or {}).pop(k, None)
            if d["name"] not in cur:
                def create():
                    s.post(f"{API}/identity-providers", body)
                    if not enabled:
                        nid = [i for i in s.get(f"{API}/identity-providers?filter=name+eq+{q(d['name'])}")["identityProviders"]][0]["id"]
                        s.patch(f"{API}/identity-providers/{nid}", [{"operation": "REPLACE", "path": "/isEnabled", "value": False}])
                    self.ok(kind, "créé")
                self.run(kind, d["name"], create)
                continue
            iid = cur[d["name"]]["id"]

            def update():
                ops = [{"operation": "REPLACE", "path": f"/{k}", "value": body[k]}
                       for k in ("description", "image", "isPrimary", "isFederationHub", "homeRealmIdentifier", "alias", "idpIssuerName")
                       if body.get(k) is not None]
                ops.append({"operation": "REPLACE", "path": "/isEnabled", "value": enabled})
                cert = body.get("certificate") or {}
                if cert.get("jwksUri"):
                    ops.append({"operation": "REPLACE", "path": "/certificate/jwksUri", "value": cert["jwksUri"]})
                have = (s.get(f"{API}/identity-providers/{iid}").get("certificate") or {}).get("certificates") or []
                for c in cert.get("certificates") or []:
                    if c not in have:  # IS refuse de remplacer par un certificat déjà présent
                        ops.append({"operation": "ADD", "path": "/certificate/certificates", "value": c})
                s.patch(f"{API}/identity-providers/{iid}", ops)
                if body.get("claims"):
                    s.put(f"{API}/identity-providers/{iid}/claims", body["claims"])
                if body.get("roles"):
                    s.put(f"{API}/identity-providers/{iid}/roles", body["roles"])
                if (body.get("provisioning") or {}).get("jit"):
                    s.put(f"{API}/identity-providers/{iid}/provisioning/jit", body["provisioning"]["jit"])
                for a in body["federatedAuthenticators"]["authenticators"]:
                    s.put(f"{API}/identity-providers/{iid}/federated-authenticators/{a['authenticatorId']}",
                          {k: v for k, v in a.items() if k != "authenticatorId"})
                self.ok(kind, "mis à jour")
            self.run(kind, d["name"], update)

    # ---------------------------------------------------------------- applications
    def apps(self):
        s = self.s
        cur = {a["name"]: a for a in s.get(f"{API}/applications?limit=500")["applications"]}
        self.app_ids = {}
        for x in self.b["apps"]:
            app, inbound, name = copy.deepcopy(x["app"]), x["inbound"], x["app"]["name"]
            if "associatedRoles" in app:  # les rôles d'app sont recréés ensuite avec l'audience de la nouvelle app
                app["associatedRoles"]["roles"] = []
            (app.get("advancedConfigurations") or {}).pop("additionalSpProperties", None)  # interne, lecture seule
            role = (app.get("claimConfiguration") or {}).get("role") or {}
            if (role.get("claim") or {}).get("uri") == "http://wso2.org/claims/role":  # claim supprimée en 7.x
                role.pop("claim")
            proto = {}
            if "oidc" in inbound:
                proto["oidc"] = {k: v for k, v in inbound["oidc"].items() if k not in ("state",)}
            if "saml" in inbound:
                proto["saml"] = {"manualConfiguration": inbound["saml"]}
            if name not in cur:
                def create():
                    s.post(f"{API}/applications", {**app, "inboundProtocolConfiguration": proto})
                    self.ok("applications", "créée")
                self.run("app", name, create)
            else:
                aid = cur[name]["id"]

                def update():
                    s.patch(f"{API}/applications/{aid}", {k: v for k, v in app.items()
                                                          # associatedRoles vide supprimerait les rôles de l'app
                                                          if k not in ("templateId", "templateVersion", "isManagementApp", "associatedRoles")})
                    if "oidc" in proto:
                        s.put(f"{API}/applications/{aid}/inbound-protocols/oidc", proto["oidc"])
                    if "saml" in proto:
                        s.put(f"{API}/applications/{aid}/inbound-protocols/saml", proto["saml"])
                    self.ok("applications", "mise à jour")
                self.run("app", name, update)
        self.app_ids = {a["name"]: a["id"] for a in s.get(f"{API}/applications?limit=500")["applications"]}
        # APIs autorisées
        for x in self.b["apps"]:
            aid = self.app_ids.get(x["app"]["name"])
            if not aid:
                continue
            have = {a["identifier"]: a for a in s.get(f"{API}/applications/{aid}/authorized-apis")}
            for z in x["authorized_apis"]:
                rid = self.api_ids.get(z["identifier"])
                if rid is None:
                    self.errors.append(f"API {z['identifier']} absente (autorisée sur {x['app']['name']})")
                    continue
                cur_sc = {sc["name"] for sc in have.get(z["identifier"], {}).get("authorizedScopes", [])}
                if z["identifier"] not in have:
                    self.run("API autorisée", f"{x['app']['name']} -> {z['identifier']}", lambda: (
                        s.post(f"{API}/applications/{aid}/authorized-apis",
                               {"id": rid, "policyIdentifier": z["policyIdentifier"], "scopes": z["scopes"]}),
                        self.ok("APIs autorisées", "ajoutée")))
                elif set(z["scopes"]) - cur_sc:
                    self.run("API autorisée", f"{x['app']['name']} -> {z['identifier']}", lambda: (
                        s.patch(f"{API}/applications/{aid}/authorized-apis/{rid}",
                                {"addedScopes": sorted(set(z["scopes"]) - cur_sc), "removedScopes": []}),
                        self.ok("APIs autorisées", "scopes ajoutés")))

    def app_roles(self):
        s = self.s
        cur = {}
        for r in s.get("/scim2/v2/Roles?count=1000").get("Resources", []):
            aud = s.get(f"/scim2/v2/Roles/{r['id']}").get("audience", {})  # absente de la vue liste
            cur[(r["displayName"], aud.get("value"))] = r["id"]
        for r in self.b["app_roles"]:
            aid = self.app_ids.get(r["app"])
            perms = [{"value": p} for p in r["permissions"]]
            rid = cur.get((r["displayName"], aid))
            if rid is None:
                self.run("rôle", r["displayName"], lambda: (s.post("/scim2/v2/Roles", {
                    "schemas": ["urn:ietf:params:scim:schemas:extension:2.0:Role"], "displayName": r["displayName"],
                    "audience": {"type": "application", "value": aid}, "permissions": perms}), self.ok("rôles d'app", "créé")))
            else:
                self.run("rôle", r["displayName"], lambda: (s.patch(f"/scim2/v2/Roles/{rid}", {
                    "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
                    "Operations": [{"op": "replace", "path": "permissions", "value": perms}]}), self.ok("rôles d'app", "mis à jour")))

    def app_templates(self):
        s = self.s
        types = {t["displayName"]: t["id"] for t in s.get(f"{API}/notification/email/template-types")}
        for x in self.b["app_email_templates"]:
            if x["type"] not in types:
                s.post(f"{API}/notification/email/template-types", {"displayName": x["type"]})
                types = {t["displayName"]: t["id"] for t in s.get(f"{API}/notification/email/template-types")}
            if x["app"] not in self.app_ids:
                self.errors.append(f"template {x['type']} : app {x['app']} absente"); continue
            aid, tid, tpl = self.app_ids[x["app"]], types[x["type"]], x["template"]
            base = f"{API}/notification/email/template-types/{tid}/app-templates/{aid}"
            exists = "_error" not in s.try_("GET", f"{base}/{tpl['locale']}")
            if exists:
                self.run("template", f"{x['type']}/{x['app']}", lambda: (s.put(f"{base}/{tpl['locale']}",
                         {k: v for k, v in tpl.items() if k != "locale"}), self.ok("templates d'app", "mis à jour")))
            else:
                self.run("template", f"{x['type']}/{x['app']}", lambda: (s.post(base, tpl), self.ok("templates d'app", "créé")))

    def go(self):
        self.prerequisites()
        for step in (self.claims, self.scopes, self.api_resources, self.idps, self.apps, self.app_roles, self.app_templates):
            step()
        for k, v in self.stats.items():
            print(f"  {k:18s} " + ", ".join(f"{n} {a}" for a, n in v.items()))
        for w in self.warnings:
            print(f"  ! {w}")
        print(f"import terminé : {len(self.errors)} erreur(s)")
        sys.exit(1 if self.errors else 0)


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "export":
        export(sys.argv[2], sys.argv[3])
    elif len(sys.argv) == 4 and sys.argv[1] == "import":
        Import(sys.argv[2], sys.argv[3]).go()
    else:
        sys.exit(__doc__)
