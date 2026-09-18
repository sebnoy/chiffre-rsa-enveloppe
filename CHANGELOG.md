# Changelog

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
