# Variante IAMCTL (identity-tools-cli)

Même périmètre que `api-migrate.py` (applications, claims custom, IdP et trusted token issuers), avec l'outil officiel
[IAMCTL](https://github.com/wso2-extensions/identity-tools-cli) en mode `exportAll` / `importAll`.

## 1. Construire IAMCTL patché (Go requis)

```bash
./build-iamctl.sh          # v3.0.1 + patches/ -> bin/iamctl
```

La v3.0.1 (dernière publiée) ne passe pas telle quelle sur ce cas :

| Patch | Problème corrigé |
|---|---|
| `0001-api-resource-url-identifiers-and-7.1-orgs.patch` | identifiant d'API resource en URL (`https://api.x/y`) : `/` dans le nom de fichier ; organisations 7.1 sans `orgHandle` |
| `0002-app-without-role-claim.patch` | application sans claim de rôle (ex. SAML en dialecte custom) : échec de l'export |

## 2. Préparer les configurations

Crée l'application M2M `iamctl-mgmt` sur chaque serveur et écrit `configs/<env>/` :

```bash
./bootstrap-mgmt-app.py https://is71.example:9443 configs/is71 7.1.0
./bootstrap-mgmt-app.py https://is73.example:9443 configs/is73 7.3.0
```

Dans `toolConfig.json`, remplacez `MON-ROLE-ORGANISATION` par vos **rôles d'organisation** :
seuls les rôles d'application doivent partir avec les SP.

## 3. Exporter (7.1)

```bash
mkdir export && cd export && ../bin/iamctl exportAll -c ../configs/is71 -o .
```

## 4. Retoucher les claims

```bash
python3 ../fix-claims.py .     # requiert PyYAML
```

La 7.3 refuse toute modification du type ou du caractère multi-valué des claims système, et l'export 7.1 ne porte pas
ces champs. Le script ne garde donc que les claims custom et convertit `multiValued` (propriété en 7.1, champ en 7.3).

## 5. Importer (7.3)

```bash
../bin/iamctl importAll -c ../configs/is73 -i .
```

## Limites par rapport à `api-migrate.py`

- Les **mappings par user store des claims système** (ex. `username` → attribut AD) sont perdus, car `fix-claims.py`
  retire les claims système.
- Les user stores référencés doivent exister sur la cible ; IAMCTL ne le vérifie pas.
- Les dépendances (API resources, IdP) doivent être dans le même run que les SP qui les utilisent.

## Sécurité

`export/` (`EXCLUDE_SECRETS: false`) et `configs/*/serverConfig.json` contiennent des secrets en clair.
Ils sont exclus par le `.gitignore`.
