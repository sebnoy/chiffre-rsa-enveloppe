# chiffre-rsa-enveloppe

Orchestration multi-destinataires : produit ou lit un fichier `.enc`
complet en combinant `chiffre-rsa-core` (scellement/descellement RSA-OAEP
de la clé de contenu) et `chiffre_aes_core` (format de fichier v2,
chiffrement symétrique). Quatre fonctions :

```rust
// Mono-fichier — pas de dépendance à chiffre_aes_core::archive.
pub fn encrypt_file_for_recipients(
    input: &Path,
    output: &Path,
    recipients: &[RecipientRef],
) -> Result<(), EnvelopeError>;

pub fn decrypt_file_with_key(
    input: &Path,
    output: &Path,
    key: &RsaKeyPair,
) -> Result<(), EnvelopeError>;

// Multi-fichiers/dossiers — voir §Archives multi-fichiers ci-dessous.
pub fn encrypt_paths_for_recipients(
    selected_paths: &[PathBuf],
    output: &Path,
    recipients: &[RecipientRef],
) -> Result<Vec<chiffre_aes_core::ArchiveWarning>, EnvelopeError>;

pub fn decrypt_paths_with_key(
    input: &Path,
    destination_dir: &Path,
    key: &RsaKeyPair,
) -> Result<Vec<chiffre_aes_core::ArchiveWarning>, EnvelopeError>;
```

# Statut

v0.1.0, pas encore publié. Dépend de `chiffre-rsa-core` (même dépôt,
`../chiffre-rsa-core`) et de `chiffre_aes_core` via une révision git
précise en attendant une release taguée incluant le header v2 — voir
[NOTICE.md](./NOTICE.md).

Ce crate ne connaît **jamais** de métadonnées ni de format JSON de
confiance (futur, confiné à `chiffre-rsa-keystore`). Il ne fait non plus
**aucune** vérification de confiance sur les clés publiques fournies :
`RecipientRef` prend une `&RsaPublicKey` telle quelle, sous l'entière
responsabilité de l'application appelante de l'avoir déjà jugée digne de
confiance (voir le cahier des charges du projet, tableau des interfaces,
Partie 2 §2).

# Comment ça s'articule

```
                    Application appelante
                    (a déjà vérifié la confiance
                     des clés publiques des destinataires)
                             │
                             ▼
                  chiffre-rsa-enveloppe   ← ce crate
     encrypt_file_for_recipients / decrypt_file_with_key
             │                                  │
             │ wrap_key / unwrap_key            │ RawKey, Recipient,
             │ (RSA-OAEP)                       │ HeaderKeyRequirement
             ▼                                  ▼
     chiffre-rsa-core                    chiffre_aes_core
     (primitives RSA)                    (format .enc, AES-GCM)
```

## Chiffrement (`encrypt_file_for_recipients`)

1. Génère une clé de contenu (CEK) aléatoire via `RawKey::generate_random()`.
2. Pour chaque destinataire, scelle cette CEK avec sa clé publique
   (`RsaPublicKey::wrap_key`) et calcule son `recipient_id` — l'empreinte
   SHA-256 de sa clé publique (`RsaPublicKey::fingerprint`). **Ce choix de
   `recipient_id` = empreinte est une décision de ce crate**, pas de
   `chiffre_aes_core` (qui traite cet identifiant comme un blob opaque)
   ni de `chiffre-rsa-core` (qui calcule l'empreinte sans savoir à quoi
   elle sert).
3. Délègue l'écriture du fichier à
   `chiffre_aes_core::encrypt_file_with_raw_key`.

## Déchiffrement (`decrypt_file_with_key`)

1. Inspecte le header via `chiffre_aes_core::inspect_key_requirement`
   (ne nécessite pas encore la clé privée).
2. Si le fichier attend un mot de passe (`HeaderKeyRequirement::Password`)
   plutôt qu'une clé externe → `EnvelopeError::NotEncryptedForKey`.
3. Sinon, cherche parmi les entrées listées celle dont `recipient_id`
   correspond à l'empreinte de `key` → `EnvelopeError::RecipientNotFound`
   si aucune ne correspond. **Ne tente jamais un descellement à
   l'aveugle** sur une entrée qui ne correspond pas : ce serait à la fois
   inutile et producteur d'une erreur RSA (`UnwrapFailed`) moins
   informative qu'un `RecipientNotFound` explicite.
4. Descelle la CEK (`RsaKeyPair::unwrap_key`) et délègue le déchiffrement
   à `chiffre_aes_core::decrypt_file_with_raw_key`.

# Archives multi-fichiers (`encrypt_paths_for_recipients`/`decrypt_paths_with_key`)

Combine `chiffre_aes_core::archive::build_archive`/`extract_archive`
(déjà utilisé pour la voie mot de passe par
`chiffre_aes_core::pipeline`, mais jamais câblé pour la voie RSA avant
ce crate) avec les mêmes primitives RSA que la voie mono-fichier. Un seul
fichier n'est qu'un cas particulier de `selected_paths` à un élément —
pas de logique dupliquée entre les deux voies au-delà de ce qui est
inhérent à l'archivage.

## Métadonnées optionnelles injectées par l'application

Deux fichiers réservés, **injectés par l'application** (pas par ce
crate — il archive simplement ce qu'on lui donne dans `selected_paths`,
sans traitement spécial pour ces noms) dans le dossier temporaire avant
l'appel, voir `FORMAT.md` §5.1 :

| Fichier | Contenu | Visible par |
|---|---|---|
| `_expediteur.json` | Document de clé signé de l'expéditeur (`chiffre-rsa-keystore`) | Uniquement les destinataires (dans le contenu chiffré) |
| `_destinataires.json` | Liste `[{ firstname, lastname, organisation, fingerprint }, ...]`, incluant l'expéditeur | Idem — effet "liste CC" voulu, pas une fuite |

Ces deux inclusions sont des choix de l'application, indépendants l'un de
l'autre. **Collision de nom** : `encrypt_paths_for_recipients` détecte
et refuse (`EnvelopeError::DuplicateArchiveEntryName`) toute paire de
chemins de `selected_paths` qui produirait la même entrée d'archive —
vérification générale, qui couvre ce cas sans traitement spécial des
deux noms réservés ; voir `FORMAT.md` §5.4 pour ce qu'elle ne couvre
**pas** (un seul fichier, par erreur nommé `_expediteur.json`, sans
collision réelle).

## Atomicité de l'extraction

`decrypt_paths_with_key` désarchive **toujours** d'abord vers un dossier
temporaire sœur de `destination_dir`, jamais directement dedans. Bascule
finale : `rename` unique si `destination_dir` n'existe pas encore ;
déplacement entrée par entrée **en deux passes** (validation intégrale,
puis déplacement seulement si aucune collision) si `destination_dir`
existe déjà — une collision détectée retourne
`EnvelopeError::DestinationConflict` sans rien déplacer. Voir `FORMAT.md`
§5.2 pour le détail, y compris la limite restante assumée (pas de
verrou inter-processus entre les deux passes).

# Ce que ce crate ne fait pas

- Pas de vérification de confiance sur les clés publiques (voir
  ci-dessus) — c'est `chiffre-rsa-keystore` + l'application appelante.
- Pas de gestion de plusieurs "tentatives" de clé privée : `decrypt_file_with_key`
  prend **une seule** `RsaKeyPair`. Un appelant qui possède plusieurs
  clés privées candidates doit les essayer lui-même (ou d'abord regarder
  les `recipient_id` via `chiffre_aes_core::inspect_key_requirement`
  directement pour savoir laquelle utiliser sans essai-erreur).
- Pas de renouvellement/révocation de destinataire sur un fichier déjà
  chiffré : ajouter/retirer un destinataire nécessite de rechiffrer le
  fichier entier (nouvelle CEK, nouveau `encrypt_file_for_recipients`) —
  cohérent avec le hors-périmètre v1 du cahier des charges (pas de
  rotation de clé).

# Tests

`src/lib.rs`, module `tests` : aller-retour mono-destinataire,
aller-retour multi-destinataires (chaque destinataire peut déchiffrer
indépendamment), rejet d'une clé qui n'est pas destinataire, rejet d'une
liste de destinataires vide, rejet d'un fichier chiffré par mot de passe
présenté à `decrypt_file_with_key`.

```bash
cargo test
```

## Fuzzing

Voir [fuzz/](./fuzz/) et [FORMAT.md](./FORMAT.md) §6. Quatre cibles :

- `decrypt_file_with_key` — contenu de fichier `.enc` arbitraire, clé
  privée fixe. Couvre la combinaison `inspect_key_requirement` →
  correspondance `recipient_id` → `unwrap_key`, propre à ce crate (ni
  `chiffre_aes_core` ni `chiffre-rsa-core` ne l'exercent seuls).
- `encrypt_decrypt_roundtrip` — test de propriété (pas de robustesse
  face à un attaquant) : contenu de fichier arbitraire chiffré puis
  déchiffré doit redonner exactement le même contenu (voie mono-fichier).
- `decrypt_paths_with_key` — même surface que `decrypt_file_with_key`,
  via la voie archive multi-fichiers.
- `encrypt_decrypt_paths_roundtrip` — même principe que
  `encrypt_decrypt_roundtrip`, mais à travers une vraie archive
  multi-entrées (`build_archive`/`extract_archive`), pas seulement un
  flux chiffré unique.

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

# Licence

MIT OR Apache-2.0.
