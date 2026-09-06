# Contribuer

Merci de l'intérêt porté à ce projet !

## Avant de proposer une PR

- Ce crate est volontairement minimal (deux fonctions publiques). Avant
  d'ajouter une nouvelle fonction ou un nouveau paramètre, vérifiez que le
  besoin ne relève pas plutôt de `chiffre-rsa-core` (primitive
  cryptographique), de `chiffre-rsa-keystore` (confiance/classification),
  ou de l'application appelante (politique métier) — voir la séparation
  des responsabilités dans le cahier des charges du projet, Partie 2 §1.
- `cargo test` doit passer, y compris les tests de bout-en-bout
  (chiffrement/déchiffrement réels sur fichiers temporaires).
- `cargo clippy -- -D warnings` doit passer.
- Toute nouvelle dépendance doit être en licence permissive (MIT,
  Apache-2.0, BSD, Zlib...). Mettez à jour [NOTICE.md](./NOTICE.md).

## Convention `recipient_id`

Si votre changement touche à la façon dont `recipient_id` est calculé
(actuellement : empreinte SHA-256 complète de la clé publique, voir
[FORMAT.md](./FORMAT.md) §1), gardez à l'esprit que ça casse la
compatibilité avec tout fichier `.enc` déjà chiffré par une version
antérieure de ce crate — `decrypt_file_with_key` ne retrouverait plus la
bonne entrée. À traiter comme un changement cassant explicite (bump de
version majeure), jamais silencieusement.

## Dépendance à `chiffre_aes_core`

Voir la même remarque dans le `CONTRIBUTING.md` de `chiffre-rsa-core` :
mettez à jour le `rev` du `Cargo.toml` explicitement dans la PR si
nécessaire, jamais via un `cargo update` implicite.

## Licence des contributions

En soumettant une contribution, vous acceptez qu'elle soit publiée sous
la même double licence MIT OR Apache-2.0 que le reste du projet.
