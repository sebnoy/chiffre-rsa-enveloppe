# Ce que produit/attend `chiffre-rsa-enveloppe`

Ce crate ne définit aucun format binaire propre — le format `.enc`
(y compris le header v2) appartient entièrement à `chiffre_aes_core`, et
l'encodage du `wrapped_key` à `chiffre-rsa-core`. Ce document spécifie
uniquement la **convention** que `chiffre-rsa-enveloppe` impose par-dessus
ces deux crates, qui autrement laissent le champ libre à l'appelant.

## 1. `recipient_id` = empreinte SHA-256 de la clé publique

`chiffre_aes_core::Recipient::recipient_id` est un `Vec<u8>` opaque au
sens du format — n'importe quel identifiant ferait l'affaire du point de
vue de `chiffre_aes_core`. `chiffre-rsa-enveloppe` fixe ce choix :
**`recipient_id` est systématiquement `RsaPublicKey::fingerprint().to_vec()`**,
32 octets, jamais tronqués, jamais préfixés.

Conséquence directe : deux fichiers `.enc` chiffrés pour le même
destinataire (même clé publique) auront le même `recipient_id`, même si
chiffrés séparément, à des dates différentes, avec des CEK différentes.
C'est voulu — c'est ce qui permet à `decrypt_file_with_key` de retrouver
la bonne entrée par une simple comparaison d'octets, sans essai-erreur.
Cela veut aussi dire qu'un observateur du fichier `.enc` (qui n'a besoin
d'aucun secret pour lire le header, voir `inspect_key_requirement`) peut
savoir *pour quelles clés publiques* un fichier a été chiffré, sans
connaître ces clés à l'avance — seulement leur empreinte. Si cette
métadonnée doit rester confidentielle dans un contexte donné, c'est à
l'application appelante de le gérer (par exemple en ne réutilisant pas la
même paire de clés entre plusieurs contextes cloisonnés) : hors du
périmètre de ce crate.

## 2. Correspondance au déchiffrement

`decrypt_file_with_key(input, output, key)` :

1. `chiffre_aes_core::inspect_key_requirement(input)` → soit
   `HeaderKeyRequirement::Password` (→ `EnvelopeError::NotEncryptedForKey`,
   ce fichier n'a jamais été chiffré par `encrypt_file_for_recipients`),
   soit `HeaderKeyRequirement::ExternalKey { recipients }`.
2. Calcule `key.public_key().fingerprint()`.
3. Cherche la première entrée de `recipients` dont `recipient_id` égale
   cette empreinte, octet pour octet. Aucune correspondance approximative,
   aucune troncature.
4. Si aucune entrée ne correspond → `EnvelopeError::RecipientNotFound`,
   **sans jamais appeler `unwrap_key`** sur une entrée qui ne correspond
   pas — inutile (on sait déjà qu'elle ne peut pas correspondre) et ça
   produirait une erreur moins informative (`RsaKeysError::UnwrapFailed`,
   indistinguable d'un ciphertext corrompu) pour un cas qui n'a rien à
   voir avec un ciphertext corrompu.
5. Si une entrée correspond, `key.unwrap_key(&entry.wrapped_key)` —
   *cette* étape peut encore échouer (`EnvelopeError::RsaKeys`) si, par
   exemple, `recipient_id` a été falsifié pour pointer vers la mauvaise
   entrée alors qu'une correspondance fortuite d'empreinte est
   pratiquement impossible (collision SHA-256) mais qu'une entrée du
   fichier a été altérée après coup.

## 3. Erreurs

`EnvelopeError` ajoute, par-dessus les erreurs remontées telles quelles de
`chiffre_aes_core::FormatError` et `chiffre_rsa_core::RsaKeysError`,
plusieurs distinctions propres à l'orchestration :

| Variante | Signification |
|---|---|
| `NoRecipients` | `encrypt_file_for_recipients`/`encrypt_paths_for_recipients` appelé avec un slice vide — rejeté *avant* d'appeler `chiffre_aes_core` (qui le rejetterait de toute façon via `FormatError::InvalidHeader`, mais avec un message moins spécifique). |
| `NotEncryptedForKey` | Le fichier inspecté attend un mot de passe, pas une clé RSA — probablement le mauvais outil de déchiffrement pour ce fichier (`chiffre_aes_core::decrypt_file` directement, avec un mot de passe). |
| `RecipientNotFound` | Aucune entrée du fichier ne correspond à l'empreinte de la clé privée fournie — cette clé n'est simplement pas un destinataire de ce fichier. |
| `Format(FormatError)` | Transparent, toute erreur remontée de `chiffre_aes_core` (fichier corrompu, tronqué, etc.). |
| `RsaKeys(RsaKeysError)` | Transparent, toute erreur remontée de `chiffre-rsa-core` lors du scellement/descellement. |
| `Archive(ArchiveError)` | Transparent, toute erreur remontée de `chiffre_aes_core::archive` (voie multi-fichiers). |
| `Io(io::Error)` | Erreur système (création de fichier/dossier temporaire, `rename`...). |
| `InvalidSelectedPath` | Un chemin de `selected_paths` n'a pas de `file_name()` exploitable (ex. `/`, `..`) — voir §5.4. |
| `DuplicateArchiveEntryName` | Deux chemins de `selected_paths` produiraient la même entrée d'archive — voir §5.4. |
| `DestinationConflict` | Extraction vers un `destination_dir` déjà existant : une entrée de premier niveau porte déjà le nom d'un élément à extraire — voir §5.2. |

## 4. Ce qui n'est PAS spécifié ici

- Le nombre maximal de destinataires par fichier : c'est la politique de
  `chiffre_aes_core` (`MAX_RECIPIENTS = 64`) qui s'applique telle quelle,
  ce crate ne la duplique ni ne la resserre.
- La taille de `wrapped_key` : entièrement déterminée par
  `chiffre-rsa-core` (512 octets pour RSA-4096-OAEP-SHA256, voir son
  propre `FORMAT.md` §5) — ce crate la transmet telle quelle sans
  l'interpréter.

## 5. Archives multi-fichiers (`encrypt_paths_for_recipients`/`decrypt_paths_with_key`)

### 5.1 Métadonnées optionnelles injectées par l'application

Deux fichiers réservés, **injectés par l'application** dans
`selected_paths` avant l'appel — ce crate ne leur applique aucun
traitement spécial, il archive tout ce qu'on lui donne, ces noms n'ont de
sens que pour l'application et pour un futur lecteur humain/outillage :

| Fichier | Contenu | Visible par |
|---|---|---|
| `_expediteur.json` | Document de clé signé de l'expéditeur (produit par `chiffre-rsa-keystore`) | Uniquement les destinataires (fait partie du contenu chiffré) |
| `_destinataires.json` | Tableau `[{ firstname, lastname, organisation, fingerprint }, ...]`, incluant l'expéditeur lui-même | Idem — effet "liste CC" voulu et documenté, pas une fuite : seuls ceux qui peuvent déchiffrer le contenu voient cette liste |

Les deux inclusions sont des choix de l'application, indépendants l'un de
l'autre. **Détection de collision** : voir §5.4 — c'est un cas particulier
d'une vérification générale (aucune entrée d'archive dupliquée), pas un
traitement spécial de ces deux noms précis.

### 5.2 Atomicité de l'extraction

`decrypt_paths_with_key` désarchive **toujours** d'abord vers un dossier
temporaire sœur de `destination_dir` — jamais directement dans
`destination_dir`, que celui-ci existe déjà ou non. Une erreur survenant
pendant l'extraction (limite de ressources, entrée malformée, disque
plein...) ne laisse donc jamais `destination_dir` dans un état
partiellement écrit : elle se manifeste avant toute écriture dans
`destination_dir` lui-même.

Bascule finale, selon que `destination_dir` existe déjà :

- **N'existe pas** : `rename` unique du dossier temporaire entier vers
  `destination_dir` — atomique sur un même système de fichiers.
- **Existe déjà** : déplacement entrée par entrée, **en deux passes**
  (voir `move_entries_into_existing_dir`) :
  1. *Validation* — pour chaque entrée de premier niveau du dossier
     temporaire, vérifie qu'aucun élément du même nom n'existe déjà dans
     `destination_dir`. Une seule collision trouvée →
     [`EnvelopeError::DestinationConflict`], **rien n'est déplacé** (pas
     même les entrées qui n'entraient en collision avec rien).
  2. *Déplacement* — uniquement si la passe de validation n'a rien
     trouvé, chaque entrée est déplacée individuellement (`rename`).

Cette approche reproduit, dans l'esprit, ce que fait
`chiffre_aes_core::pipeline::finalize_extraction` pour la voie mot de
passe (dont le code n'est pas directement réutilisable ici : fonction
privée au module `pipeline` de `chiffre_aes_core`) — sans toutefois
tenter une fusion récursive de sous-dossiers homonymes plus profonds
qu'un premier niveau : une collision au niveau racine
(`destination_dir/nom_qui_collisionne`) est détectée que ce soit un
fichier ou un dossier, mais le contenu d'un dossier n'est jamais
fusionné avec un dossier homonyme déjà présent — l'un ou l'autre existe,
jamais un mélange des deux.

**Limite restante, assumée** : entre la passe de validation et la passe
de déplacement, une modification concurrente de `destination_dir` par un
autre processus reste possible (absence de verrouillage inter-processus)
— hors de portée de ce qu'une fonction synchrone, sans dépendance
supplémentaire, peut garantir seule.

### 5.3 Bug corrigé : fuite mémoire sur la bascule atomique (trouvé par fuzzing)

La première version de la branche "bascule atomique" (cas
`destination_dir` absent) utilisait `std::mem::forget(tmp_extract_dir)`
après le `rename` pour empêcher `TempDir` de tenter de supprimer un
chemin qui n'existe plus. `mem::forget` est sûr en Rust (jamais de
comportement indéfini), mais il abandonne la **valeur entière**,
mémoire tas comprise — `TempDir` contient un `PathBuf` interne, alloué
sur le tas, jamais libéré dans ce chemin. C'est une fuite mémoire réelle,
détectée par LeakSanitizer lors d'une campagne
`cargo +nightly fuzz run encrypt_decrypt_paths_roundtrip` : cette cible
emprunte ce chemin de code à **chaque itération** (aller-retour toujours
réussi par construction), donc la fuite s'est manifestée dès la première
exécution, sans nécessiter d'entrée particulière.

Corrigé en remplaçant `mem::forget` par `TempDir::keep()` (méthode dédiée
à cet usage précis — désarmer la suppression automatique tout en
restituant proprement le `PathBuf`, sans rien perdre en mémoire).
Nécessite `tempfile` ≥ 3.20.0 (`keep()` renommée depuis `into_path()`
dans cette version) — voir `Cargo.toml`.

### 5.4 Détection de collision de noms d'entrée d'archive

`encrypt_paths_for_recipients` vérifie, **avant** toute écriture (avant
même de créer le fichier temporaire d'archive), qu'aucun couple de
chemins dans `selected_paths` ne produirait la même entrée dans l'archive
(même `Path::file_name()`, indépendamment du dossier d'origine). Une
collision trouvée → [`EnvelopeError::DuplicateArchiveEntryName`], rien
n'est écrit.

Cette vérification est **générale** — elle ne connaît rien des noms
`_expediteur.json`/`_destinataires.json` en particulier. Elle les couvre
néanmoins entièrement : si l'application sélectionne par erreur un
fichier de contenu réel nommé `_expediteur.json` *en plus* du vrai
document de métadonnées portant ce même nom, c'est une collision comme
une autre, détectée de la même façon.

**Ce que ça ne couvre pas** : si l'application inclut un fichier de
contenu réel nommé `_expediteur.json` **sans** inclure de véritable
document de métadonnées à côté, il n'y a — par définition — aucune
collision au sens de cette vérification (un seul chemin porte ce nom).
Le fichier sera archivé sous ce nom et un lecteur qui applique la
convention `chiffre-rsa-keystore` pourrait à tort l'interpréter comme un
document de clé. Cette API n'a aucun moyen de distinguer "l'application
a délibérément voulu ce nom pour du contenu ordinaire" de "l'application
s'est trompée" — seule l'application, qui connaît l'intention, peut
éviter ce cas.

## 6. Fuzzing

Voir [fuzz/](./fuzz/) (`cargo-fuzz`, toolchain nightly).

| Cible | Entrée fuzzée | Ce qu'elle exerce |
|---|---|---|
| `decrypt_file_with_key` | contenu de fichier `.enc` arbitraire, contre une clé privée RSA fixe | `inspect_key_requirement` → recherche de `recipient_id` correspondant → `unwrap_key`, spécifique à ce crate. |
| `encrypt_decrypt_roundtrip` | contenu de fichier arbitraire, chiffré puis déchiffré pour un unique destinataire fixe | Propriété d'aller-retour (identité) sur des contenus que les tests unitaires n'énumèrent pas (octets nuls, tailles inhabituelles, motifs répétitifs). |
| `decrypt_paths_with_key` | contenu de fichier `.enc` arbitraire, contre une clé privée RSA fixe | Même surface que `decrypt_file_with_key`, mais via la voie archive multi-fichiers ; en pratique, la quasi-totalité des entrées aléatoires n'atteignent jamais `extract_archive` (échec d'authentification AEAD avant), voir la cible suivante pour ça. |
| `encrypt_decrypt_paths_roundtrip` | DEUX contenus de fichiers arbitraires (dérivés d'un seul buffer, découpé), chiffrés en une archive puis déchiffrés | Propriété d'aller-retour à travers une VRAIE archive multi-entrées (`build_archive`/`extract_archive`), pas seulement l'AEAD d'un flux unique. |

Les deux cibles utilisent une clé RSA-4096 **fixe** (même clé que
`chiffre-rsa-core/tests/vectors/fixed_test_key.pem`, copiée dans
`fuzz/fixed_key.pem`) — générer une paire à chaque itération serait
prohibitif sans rien apporter à la propriété recherchée.

`decrypt_file_with_key` n'a besoin d'aucune entrée valide pour être utile
(l'essentiel de la surface intéressante est déjà atteinte par le rejet
précoce d'un header malformé) ; `encrypt_decrypt_roundtrip`, à l'inverse,
est un test de propriété — un panic y indique un vrai bug de ce crate,
pas un comportement attendu face à une entrée hostile.

## 7. Statut

Document à jour à la date de rédaction (crate v0.1.0). Si un jour
`recipient_id` cesse d'être l'empreinte complète (par exemple pour des
raisons de taille de header avec un très grand nombre de destinataires),
ce fichier fait foi sur la convention réellement appliquée, indépendamment
de l'implémentation.