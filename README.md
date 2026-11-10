# chiffre-rsa-enveloppe

Orchestration multi-destinataires : produit ou lit un fichier `.enc`
complet en combinant `chiffre-rsa-core` (scellement RSA-OAEP de la clé de
contenu, signature RSA-PSS de l'expéditeur) et `chiffre_aes_core` (format
v3 : chiffrement symétrique, engagement de clé, signature obligatoire).

```rust
// Fichier unique
pub fn encrypt_file_for_recipients(input: &Path, output: &Path,
    recipients: &[RecipientRef], sender: &RsaKeyPair) -> Result<(), EnvelopeError>;
pub fn decrypt_file_with_key(input: &Path, output: &Path, key: &RsaKeyPair,
    expected_senders: &[RsaPublicKey]) -> Result<Fingerprint, EnvelopeError>;

// En mémoire : aucun fichier temporaire, aucun clair sur disque
pub fn encrypt_bytes_for_recipients(plaintext: &[u8],
    recipients: &[RecipientRef], sender: &RsaKeyPair) -> Result<Vec<u8>, EnvelopeError>;
pub fn decrypt_bytes_with_key(container: &[u8], key: &RsaKeyPair,
    expected_senders: &[RsaPublicKey]) -> Result<(Zeroizing<Vec<u8>>, Fingerprint), EnvelopeError>;

// Premier message d'un expéditeur inconnu : sa clé est trouvée dans le contenu
// par `present`, après vérification de son certificat par l'application (2.1.0)
pub fn decrypt_bytes_with_key_from_presented_sender(container: &[u8], key: &RsaKeyPair,
    present: impl Fn(&[u8]) -> Option<RsaPublicKey>) -> Result<(Zeroizing<Vec<u8>>, Fingerprint), EnvelopeError>;

// Fichiers et dossiers
pub fn encrypt_paths_for_recipients(selected_paths: &[PathBuf], output: &Path,
    recipients: &[RecipientRef], sender: &RsaKeyPair) -> Result<Vec<ArchiveWarning>, EnvelopeError>;
pub fn decrypt_paths_with_key(input: &Path, destination_dir: &Path, key: &RsaKeyPair,
    expected_senders: &[RsaPublicKey]) -> Result<(Vec<ArchiveWarning>, Fingerprint), EnvelopeError>;

// Sans secret : expéditeur annoncé et destinataires
pub fn inspect_file(input: &Path) -> Result<EnvelopeInfo, EnvelopeError>;
pub fn inspect_bytes(container: &[u8]) -> Result<EnvelopeInfo, EnvelopeError>;
```

# Statut

v2.1.0. Dépend de `chiffre_aes_core` v3.1.0 et de `chiffre-rsa-core`
v2.0.1 (tags Git) — voir [NOTICE.md](./NOTICE.md). **Les fichiers des
versions 1.x (format v2) ne sont plus lisibles** : ce format ne protégeait
pas contre un destinataire et n'identifiait pas l'expéditeur.

Ce crate ne fait **aucune** vérification de confiance sur les clés
publiques : celles des destinataires (`RecipientRef`) et des expéditeurs
attendus sont choisies par l'application appelante, sous sa
responsabilité (par exemple avec `chiffre-rsa-keystore`).

# Comment ça s'articule

```
                    Application appelante
          (a déjà jugé dignes de confiance les clés des
           destinataires et des expéditeurs attendus)
                             │
                             ▼
                  chiffre-rsa-enveloppe   ← ce crate
             │                                  │
             │ wrap_key / unwrap_key (OAEP)     │ RawKey, Recipient,
             │ sign / verify (PSS)              │ SenderSigner, SenderVerifier
             ▼                                  ▼
     chiffre-rsa-core                    chiffre_aes_core
     (primitives RSA)                    (format .enc v3, AES-GCM)
```

## Chiffrement

1. Génère une clé de contenu (CEK) aléatoire (`RawKey::generate_random()`).
2. La scelle pour chaque destinataire (`RsaPublicKey::wrap_key`), avec
   comme `recipient_id` l'empreinte SHA-256 de sa clé publique — choix de
   ce crate, voir `FORMAT.md` §1.
3. Délègue l'écriture à `chiffre_aes_core`, qui fait signer le fichier
   par `sender` (RSA-PSS sur l'empreinte du fichier, préfixée — voir
   `FORMAT.md` §2.1).

## Déchiffrement

1. Lit l'en-tête sans secret ; un fichier chiffré par mot de passe →
   `NotEncryptedForKey`.
2. Cherche l'entrée dont `recipient_id` correspond à l'empreinte de `key`
   → `RecipientNotFound` sinon. **Jamais de descellement à l'aveugle.**
3. Descelle la CEK, puis `chiffre_aes_core` vérifie l'engagement de clé et
   la signature : accepté seulement si l'expéditeur est l'une des clés de
   `expected_senders` (sinon `SenderNotVerified`, rien n'est livré). La
   fonction renvoie l'empreinte de l'expéditeur vérifié.

# Archives multi-fichiers

Confiées à `chiffre_aes_core::encrypt_paths_for_recipients` /
`decrypt_to_dir_from_sender` : archive intermédiaire chiffrée sous une
clé éphémère (plus aucun clair sur disque, contrairement aux versions
1.x), extraction seulement après vérification complète, dossier
temporaire privé, aucun écrasement, écriture durable. Voir `FORMAT.md`
§5.2.

## Métadonnées optionnelles injectées par l'application

Deux fichiers réservés, **injectés par l'application** dans
`selected_paths` (ce crate les archive tels quels), voir `FORMAT.md` §5.1 :

| Fichier | Contenu | Visible par |
|---|---|---|
| `_expediteur.json` | Document de clé signé de l'expéditeur (`chiffre-rsa-keystore`) | Uniquement les destinataires (dans le contenu chiffré) |
| `_destinataires.json` | Liste `[{ firstname, lastname, organisation, fingerprint }, ...]`, incluant l'expéditeur | Idem — effet "liste CC" voulu, pas une fuite |

**Collision de nom** : deux chemins qui produiraient la même entrée
d'archive sont refusés (`DuplicateArchiveEntryName`) — voir `FORMAT.md`
§5.4, y compris ce que cette vérification ne couvre pas.

# Ce que ce crate ne fait pas

- Pas de vérification de confiance sur les clés publiques (voir
  ci-dessus).
- Pas de fraîcheur : un fichier signé reste valide et peut être renvoyé
  tel quel ; une date ou un numéro de version relèvent du contenu.
- Pas de gestion de plusieurs clés privées candidates : `inspect_file`
  donne les empreintes des destinataires pour choisir la bonne.
- Pas d'ajout ou de retrait de destinataire sur un fichier existant : il
  faut le rechiffrer.

# Tests

`src/lib.rs`, module `tests` : allers-retours (fichier, mémoire,
archives ; un ou plusieurs destinataires), expéditeur vérifié renvoyé,
refus d'un expéditeur non attendu, d'une empreinte usurpée et d'une
signature faite pour un autre usage (sans le préfixe), sans aucune sortie
ni temporaire ; clé non destinataire, listes vides, fichier chiffré par
mot de passe, collisions de noms et de destination.

```bash
cargo test --release   # génération RSA-4096 : bien plus rapide en release
```

## Fuzzing

Voir [fuzz/](./fuzz/) et [FORMAT.md](./FORMAT.md) §6. Quatre cibles :

- `decrypt_file_with_key` — contenu de fichier `.enc` arbitraire, clé
  privée fixe (seule expéditrice attendue). Couvre la combinaison lecture
  de l'en-tête → correspondance `recipient_id` → `unwrap_key` →
  vérification de l'expéditeur, propre à ce crate.
- `encrypt_decrypt_roundtrip` — test de propriété (pas de robustesse
  face à un attaquant) : contenu de fichier arbitraire chiffré puis
  déchiffré doit redonner exactement le même contenu (voie mono-fichier).
- `decrypt_paths_with_key` — même surface que `decrypt_file_with_key`,
  via la voie archive multi-fichiers.
- `encrypt_decrypt_paths_roundtrip` — même principe que
  `encrypt_decrypt_roundtrip`, mais à travers une vraie archive
  multi-entrées, pas seulement un flux chiffré unique.

```bash
cargo +nightly fuzz run decrypt_file_with_key -- -max_total_time=120
cargo +nightly fuzz run encrypt_decrypt_roundtrip -- -max_total_time=120
cargo +nightly fuzz run decrypt_paths_with_key -- -max_total_time=120
cargo +nightly fuzz run encrypt_decrypt_paths_roundtrip -- -max_total_time=120
```

Pour un seed réaliste de `decrypt_paths_with_key` (un vrai `.enc`
multi-fichiers plutôt que le squelette `ENC1`+zéros fourni par défaut) :

```bash
cargo run --example gen_paths_seed -- seed.enc fichier1.txt fichier2.txt
cp seed.enc fuzz/corpus/decrypt_paths_with_key/
```


# Compilation

Mêmes prérequis que `chiffre-rsa-core` : toolchain Rust ≥ 1.85
(édition 2024, requise transitivement par `chiffre_aes_core` →
`aes-gcm 0.11`).

# Transparence et réutilisation

Comme le reste de l'écosystème `chiffre-*`, ce crate documente ses
choix (y compris ceux qu'il ne fait pas, cf. "Ce que ce crate ne fait
pas" ci-dessus) pour que quiconque l'évalue ou le réutilise puisse le
faire en connaissance de cause, sans avoir à relire le code source
pour en retrouver les hypothèses.

# Licence

MIT OR Apache-2.0.
