# Changelog

## v1.1.1

Version de maintenance issue d'un audit selon le *Guide de développement
sécurisé en Rust* de l'ANSSI. **Aucun changement de code, de format ni
d'API.**

- **Dépendances : tags `v2.1.1`** de `chiffre-aes-core` et **`v1.2.1`** de
  `chiffre-rsa-core` (versions de maintenance). Une application qui utilise
  plusieurs de ces crates doit les prendre aux mêmes tags, faute de quoi
  `Password`, `RawKey` et les clés RSA existent en deux versions
  incompatibles.
- **Dépendances** — `ctutils` 0.4.5 dans `Cargo.lock` et `fuzz/Cargo.lock`
  (RUSTSEC-2026-0385 : opérations qui n'étaient pas en temps constant).
  `fuzz/Cargo.lock`, resté sur les versions 0.1.0 des crates locales, est
  réaligné sur `fuzz/Cargo.toml`.
- **RUSTSEC-2023-0071 (« Marvin », crate `rsa`)** — aucune version corrigée
  n'existe. L'avis est ignoré dans `.cargo/audit.toml` (racine et `fuzz`)
  avec sa justification (le descellement de la clé de contenu s'exécute sur
  l'appareil du destinataire).
- **`scripts/verifier.sh`** — enchaîne `clippy` (avertissements refusés),
  `cargo audit` et les tests ; `cargo audit` seul pour `fuzz`.
- Tests : les 13 tests passent inchangés ; `clippy` : aucun avertissement.

## v1.1.0
Ajout variable d'environnement : pub const VERSION


## v1.0.0

Première version publiée de `chiffre-rsa-enveloppe` — orchestration
multi-destinataires : produit/lit un `.enc` complet en combinant
`chiffre-aes-core` (cœur symétrique) et `chiffre-rsa-core` (scellement
RSA-OAEP de la clé de contenu).

- **Chiffrement/déchiffrement fichier unique** —
  `encrypt_file_for_recipients`/`decrypt_file_with_key`.
- **Archives multi-fichiers** —
  `encrypt_paths_for_recipients`/`decrypt_paths_with_key`, avec
  extraction atomique (voir [FORMAT.md](./FORMAT.md)).
- **Métadonnées optionnelles injectées par l'application** — voir
  README pour le détail des champs supportés.
- **Aucune vérification de confiance sur les clés publiques** —
  `RecipientRef` prend une `&RsaPublicKey` telle quelle, sous l'entière
  responsabilité de l'application appelante de l'avoir déjà jugée
  digne de confiance (délégué à `chiffre-rsa-keystore` en amont).
- **`decrypt_file_with_key` prend une seule clé privée** — pas de
  gestion de plusieurs tentatives ; un appelant avec plusieurs clés
  candidates doit soit les essayer lui-même, soit inspecter
  `recipient_id` via `chiffre_aes_core::inspect_key_requirement` en
  amont.
- **Pas de renouvellement/révocation de destinataire** sur un fichier
  déjà chiffré — cohérent avec le hors-périmètre v1 du cahier des
  charges (pas de rotation de clé) ; ajouter/retirer un destinataire
  nécessite un rechiffrement complet.
- **Dépendances** : `chiffre-rsa-core` v1.0.0 et `chiffre_aes_core`
  v2.0.0 (tags Git, pas encore publiées sur crates.io) — voir
  [NOTICE.md](./NOTICE.md) pour l'état exact de cette chaîne de
  dépendances.
- Campagnes de fuzzing — voir [fuzz/](./fuzz/).
- Aucun audit de sécurité externe réalisé à ce jour.
