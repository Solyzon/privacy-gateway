<div align="center">
  <h1>privacy-gateway</h1>

  <p>La passerelle locale qui masque les secrets et les données personnelles avant qu'ils partent chez Anthropic, pour l'équipe Solyzon.</p>

  <p>
    <img alt="Go" src="https://img.shields.io/badge/Go-1.26-00ADD8?style=flat-square&logo=go&logoColor=white">
    <img alt="License" src="https://img.shields.io/badge/license-proprietary-red?style=flat-square">
  </p>
</div>

## Stack

Un binaire Go sans dépendance externe, posé en `ANTHROPIC_BASE_URL` de Claude Code sur
`127.0.0.1:8787` et relancé par `launchd` sur macOS ou `systemd --user` sur Linux. Les repères
`SZ_<KIND>_<12 hex>` sont un HMAC de la valeur avec une clé propre à la machine, donc rien n'est
écrit sur disque et le même historique donne les mêmes octets d'un tour à l'autre, ce qui garde
le cache de prompts d'Anthropic.

## Fonctionnalités

- Masque les secrets (clés d'API, jetons, mots de passe de `.env`, YAML et JSON, clés privées), les noms et adresses postales des personnes, les e-mails, téléphones, IBAN, numéros de sécurité sociale et cartes bancaires.
- Remet les vraies valeurs dans la réponse en flux et dans les commandes que Claude lance.
- Affiche dans la statusline, pendant deux secondes et par session, ce qui vient d'être masqué.
- Audite le poste et sort en erreur au moindre trou : service arrêté, réglage absent, canari qui fuit, programme qui parle à Anthropic sans passer par la passerelle, erreurs en série.

## Lancement (dev)

Go 1.26 et pnpm, installés par `mise install`.

```bash
make verify
make dev
```

`make dev` lance une passerelle de test sur `127.0.0.1:8788`, sans toucher au réglage de
Claude Code.

Commandes courantes :

```bash
make verify    # format, analyse et tests
make live      # test réel avec Claude Code derrière un enregistreur
make install   # installe la passerelle sur ce poste et y branche Claude Code
```

Couper en urgence : `~/.solyzon/privacy-gateway/bin/privacy-gateway uninstall`.

## Documentation

| Fichier                                                                                                          | Contenu                                                    |
| ---------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------- |
| [`CLAUDE.md`](./CLAUDE.md)                                                                                       | Règles projet et invariants                                |
| [`docs/privacy-gateway.md`](./docs/privacy-gateway.md)                                                           | Ce qui est masqué, installation, audit, pannes, statusline |
| [`docs/superpowers/plans/2026-10-29-privacy-gateway.md`](./docs/superpowers/plans/2026-10-29-privacy-gateway.md) | Lots faits et à faire                                      |

## Branches et publication

| Branche | Rôle                                 |
| ------- | ------------------------------------ |
| `dev`   | Branche de travail, celle par défaut |

Le binaire se publie par étiquette `vX.Y.Z`. Il n'y a ni déploiement ni aperçu.

## Auteurs

Conçu et développé par **[Armand OCTEAU](https://github.com/Pomme978)** et
**[Sarah LÉVY](https://github.com/Saaaraaah14)** au sein de [Solyzon](https://solyzon.com),
à partir d'octobre 2026.

## Licence

Travail propriétaire. **Copyright (c) 2026 Solyzon. Tous droits réservés.**

Outil interne de Solyzon, réservé à son équipe. Toute reproduction, redistribution,
modification ou utilisation par un tiers est interdite sans autorisation écrite préalable.

<div align="center">
  <br>
  <a href="https://solyzon.com">
    <img src="./docs/assets/solyzon.svg" alt="Solyzon" height="48">
  </a>
  <p><sub>Conception et développement par Solyzon.</sub></p>
  <p><sub>© 2026 Solyzon. Tous droits réservés.</sub></p>
</div>
