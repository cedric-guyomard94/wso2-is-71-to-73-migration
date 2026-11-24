# Migration WSO2 Identity Server 7.1 → 7.3 (API REST)

Migre les **applications (SP)**, les **claims** et les **connexions** (IdP fédérés et trusted token issuers)
d'un WSO2 IS 7.1 vers un IS 7.3 via les API REST de management, sans IAMCTL.
Python 3, bibliothèque standard uniquement.

## Utilisation

L'export et l'import sont séparés : chacun ne contacte qu'un seul serveur.

```bash
./api-migrate.py export https://is71.example:9443 bundle.json   # sur la 7.1
./api-migrate.py import bundle.json https://is73.example:9443   # sur la 7.3
```

Utilisateur et mot de passe admin sont demandés à chaque exécution, avec un mot de passe masqué qui ne finit ni dans
l'historique du shell ni dans les logs. Pour l'automatisation, `IS_USER` et `IS_PASSWORD` sont lus s'ils sont définis.

L'import est idempotent : il crée ce qui manque, met à jour l'existant et peut être relancé sans effet de bord.
Code retour non nul en cas d'erreur.

## Périmètre

| Objet | Détail |
|---|---|
| Claims locales custom | y compris `multiValued` (propriété en 7.1, champ en 7.3) et mappings par user store |
| Claims système | seuls les mappings d'attributs par user store et `ExcludedUserStores` sont repris ; type et reste de la claim 7.3 conservés |
| Dialectes et claims externes | mapping d'une claim externe mis à jour seulement s'il vise une claim custom |
| Scopes OIDC | union des claims 7.1 et 7.3 |
| API resources | type BUSINESS, avec scopes |
| IdP fédérés et trusted token issuers | authenticators, claims, rôles, JIT, certificats PEM ou JWKS, `idpIssuerName`, alias |
| Applications OIDC / OAuth2 / SAML | `client_id` et secret conservés, certificat ou JWKS client, APIs autorisées |
| Rôles d'application | recréés avec l'audience de la nouvelle application |
| Templates e-mail par application | |

Écarts 7.1 → 7.3 traités : `multiValued`, champs refusés en écriture (`isEnabled`, `realm`, id des scopes,
`additionalSpProperties`), `implicitAssociation` désactivée, claims d'IdP à `uri: null`,
claim `http://wso2.org/claims/role` supprimée, certificat d'IdP déjà présent.

## Variante IAMCTL

Une recette équivalente avec l'outil officiel IAMCTL (patché) est dans [`iamctl/`](iamctl/README.md).
Elle perd les mappings par user store des claims système.

## Prérequis

- Les **user stores** ne sont pas migrés : ceux référencés par les mappings de claims doivent exister sur la cible.
  Le script le vérifie avant de toucher à la 7.3.
- Compte administrateur sur les deux serveurs.
- Le certificat TLS n'est pas vérifié (environnements internes).

## Non couvert

- Affectations d'utilisateurs et de groupes aux rôles, user stores, organisations, branding, connecteurs de gouvernance.
- Modifications des claims système autres que les mappings (libellés, regex…), claims retirées d'un scope standard.
- Hash des secrets (`hash_tokens_and_secrets`), authenticators custom, tokens et sessions.
- WS-Federation / WS-Trust, branding d'application, applications partagées, provisioning sortant.

## Sécurité

`bundle.json` contient les **secrets** (client secrets, secrets des IdP) en clair : le transférer par un canal sûr
et le supprimer après import. Il est exclu par le `.gitignore`.

## Licence

MIT
