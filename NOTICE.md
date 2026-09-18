# Notices tierces

⚠️ Point de départ manuel, à régénérer à chaque changement de dépendances :

```bash
cargo install cargo-about   # ou cargo-license
cargo about generate about.hbs > NOTICE.md
```

## Dépendances directes

| Crate | Licence |
|---|---|
| chiffre-rsa-core | MIT OR Apache-2.0 (v1.0.0, tag Git — voir sa propre `NOTICE.md`) |
| chiffre_aes_core | MIT OR Apache-2.0 (v2.0.0, tag Git — voir sa propre `NOTICE.md`) |
| thiserror | MIT OR Apache-2.0 |
| tempfile | MIT OR Apache-2.0 — passé de dépendance de développement à dépendance normale (utilisée par `encrypt_paths_for_recipients`/`decrypt_paths_with_key` pour les fichiers/dossiers temporaires) |

## Dépendances de développement uniquement (tests)

| Crate | Licence |
|---|---|
| zeroize | Apache-2.0 OR MIT |

## Dépendances transitives

Toutes celles de `chiffre-rsa-core` (voir sa `NOTICE.md`) s'appliquent
également ici par transitivité. Aucune dépendance transitive
supplémentaire propre à ce crate au-delà de `thiserror`/`tempfile`
elles-mêmes (MIT OR Apache-2.0, sans dépendance non triviale). À
reconfirmer avec `cargo about`/`cargo license` avant toute release.
