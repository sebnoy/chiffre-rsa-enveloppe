# Notices tierces

⚠️ Point de départ manuel, à régénérer à chaque changement de dépendances :

```bash
cargo install cargo-about   # ou cargo-license
cargo about generate about.hbs > NOTICE.md
```

## Dépendances directes

| Crate | Licence |
|---|---|
| chiffre-rsa-core | MIT OR Apache-2.0 (v2.0.1, tag Git — voir sa propre `NOTICE.md`) |
| chiffre_aes_core | MIT OR Apache-2.0 (v3.1.0, tag Git — voir sa propre `NOTICE.md`) |
| thiserror | MIT OR Apache-2.0 |
| zeroize | Apache-2.0 OR MIT — clair renvoyé par `decrypt_bytes_with_key`, effacé à sa destruction |

## Dépendances de développement uniquement (tests)

| Crate | Licence |
|---|---|
| tempfile | MIT OR Apache-2.0 — redevenu dépendance de test en 2.0.0 : les fichiers et dossiers temporaires sont gérés par `chiffre_aes_core` |

## Dépendances transitives

Toutes celles de `chiffre-rsa-core` (voir sa `NOTICE.md`) s'appliquent
également ici par transitivité. Aucune dépendance transitive
supplémentaire propre à ce crate au-delà de `thiserror`/`zeroize`
elles-mêmes (MIT OR Apache-2.0, sans dépendance non triviale). À
reconfirmer avec `cargo about`/`cargo license` avant toute release.
