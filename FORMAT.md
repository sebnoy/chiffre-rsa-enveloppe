# Ce que produit/attend `chiffre-rsa-enveloppe`

Ce crate ne définit aucun format binaire propre — le format `.enc`
(format v3 depuis la 2.0.0 de ce crate, voir `chiffre_aes_core`
`FORMAT.md` §12) appartient entièrement à `chiffre_aes_core`, et
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
d'aucun secret pour lire le header, voir `inspect_file`) peut
savoir *pour quelles clés publiques* un fichier a été chiffré, sans
connaître ces clés à l'avance — seulement leur empreinte. Si cette
métadonnée doit rester confidentielle dans un contexte donné, c'est à
l'application appelante de le gérer (par exemple en ne réutilisant pas la
même paire de clés entre plusieurs contextes cloisonnés) : hors du
périmètre de ce crate.

## 2. Correspondance au déchiffrement

`decrypt_file_with_key(input, output, key, expected_senders)` (même
principe pour `decrypt_bytes_with_key` et `decrypt_paths_with_key`) :

1. Un conteneur v1 (mot de passe) → `EnvelopeError::NotEncryptedForKey`,
   ce fichier n'a jamais été produit par ce crate. Sinon,
   `chiffre_aes_core::inspect_recipients` lit les destinataires sans secret.
2. Calcule `key.public_key().fingerprint()`.
3. Cherche la première entrée dont `recipient_id` égale cette empreinte,
   octet pour octet. Aucune correspondance approximative, aucune
   troncature.
4. Aucune entrée → `EnvelopeError::RecipientNotFound`, **sans jamais
   appeler `unwrap_key`** sur une entrée qui ne correspond pas.
5. Sinon, `key.unwrap_key(&entry.wrapped_key)` (RSA-OAEP), puis
   déchiffrement par `chiffre_aes_core`, qui vérifie l'engagement de clé
   puis la signature de l'expéditeur (§2.1) avant de livrer quoi que ce
   soit.

## 2.1 Signature de l'expéditeur

Chaque fichier est signé par la clé RSA de son expéditeur, celle qui sert
aussi à déchiffrer ce qu'on lui envoie.

- `sender_id` (en clair dans l'en-tête) = `RsaPublicKey::fingerprint()`
  de la clé de l'expéditeur, 32 octets.
- Message signé, en RSA-PSS-SHA256 (`chiffre-rsa-core`, signature
  aveuglée) :

  ```
  "chiffre-rsa-enveloppe v2 signature de l'expediteur" || 0x00 || transcript
  ```

  où `transcript` est l'empreinte de tout le fichier calculée par
  `chiffre_aes_core` (son `FORMAT.md` §12.4). Le préfixe empêche qu'une
  signature de fichier soit acceptée pour un autre usage de la même clé
  (messages, répertoires d'une application), et inversement.
- Au déchiffrement, l'appelant fournit la liste des clés publiques
  **attendues** (`expected_senders`, non vide, sinon
  `NoExpectedSenders`). Le fichier est accepté seulement si `sender_id`
  est l'empreinte de l'une d'elles **et** si la signature est valide pour
  elle ; la fonction renvoie alors cette empreinte. Sinon
  `SenderNotVerified`, et rien n'est livré (ni fichier de sortie, ni
  temporaire, ni extraction).
- `inspect_file` / `inspect_bytes` donnent l'expéditeur **annoncé** sans
  secret, pour choisir la liste des expéditeurs attendus ; il n'est
  vérifié qu'au déchiffrement.

La même paire RSA sert au chiffrement (OAEP) et à la signature (PSS),
comme dans les applications qui l'utilisent déjà ; les deux usages
restent séparés par leur encodage.

## 3. Erreurs

`EnvelopeError` ajoute, par-dessus les erreurs remontées telles quelles de
`chiffre_aes_core::FormatError` et `chiffre_rsa_core::RsaKeysError`,
plusieurs distinctions propres à l'orchestration :

| Variante | Signification |
|---|---|
| `NoExpectedSenders` | Déchiffrement appelé sans aucun expéditeur attendu. |
| `SenderNotVerified` | Fichier signé par une clé qui n'est pas dans `expected_senders`, ou signature invalide (fichier modifié, y compris par un destinataire). Rien n'est livré. |
| `NoRecipients` | `encrypt_file_for_recipients`/`encrypt_paths_for_recipients` appelé avec un slice vide — rejeté *avant* d'appeler `chiffre_aes_core` (qui le rejetterait de toute façon via `FormatError::InvalidHeader`, mais avec un message moins spécifique). |
| `NotEncryptedForKey` | Le fichier inspecté attend un mot de passe, pas une clé RSA — probablement le mauvais outil de déchiffrement pour ce fichier (`chiffre_aes_core::decrypt_file` directement, avec un mot de passe). |
| `RecipientNotFound` | Aucune entrée du fichier ne correspond à l'empreinte de la clé privée fournie — cette clé n'est simplement pas un destinataire de ce fichier. |
| `Format(FormatError)` | Transparent, toute erreur remontée de `chiffre_aes_core` (fichier corrompu, tronqué, clé incorrecte d'après l'engagement, etc.). |
| `RsaKeys(RsaKeysError)` | Transparent, toute erreur remontée de `chiffre-rsa-core` lors du scellement/descellement. |
| `Archive(ArchiveError)` | Transparent, toute erreur remontée de `chiffre_aes_core::archive` (voie multi-fichiers). |
| `Io(io::Error)` | Erreur système. |
| `InvalidSelectedPath` | Un chemin de `selected_paths` n'a pas de `file_name()` exploitable (ex. `/`, `..`) — voir §5.4. |
| `DuplicateArchiveEntryName` | Deux chemins de `selected_paths` produiraient la même entrée d'archive — voir §5.4. |
| `DestinationConflict` | Extraction vers un `destination_dir` déjà existant : une entrée de premier niveau porte déjà le nom d'un élément à extraire ; le message indique laquelle — voir §5.2. |

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

Depuis la 2.0.0, l'archivage et l'extraction sont confiés à
`chiffre_aes_core::encrypt_paths_for_recipients` /
`decrypt_to_dir_from_sender`, qui offrent les mêmes garanties que la voie
par mot de passe :

- l'archive intermédiaire est **chiffrée** sous une clé éphémère gardée en
  mémoire : aucun clair sur disque, même après un arrêt brutal (la version
  1.x écrivait l'archive en clair à côté du `.enc`) ;
- rien n'est extrait avant la vérification complète du fichier, signature
  comprise ;
- extraction dans un dossier temporaire privé (`0700`), puis bascule :
  `rename` unique si `destination_dir` n'existe pas ; sinon refus, **sans
  rien déplacer**, si un élément de premier niveau existe déjà
  (`DestinationConflict`), puis déplacement entrée par entrée ;
- résultat écrit sur le disque (`fsync`/`syncfs`) avant d'annoncer la
  réussite.

**Limite restante** : lorsque `destination_dir` existe déjà, un
déplacement peut encore échouer après d'autres (disque plein,
modification concurrente) ; voir le README de `chiffre_aes_core`.

### 5.3 Bug corrigé : fuite mémoire sur la bascule atomique (trouvé par fuzzing, version 1.x)

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

`encrypt_paths_for_recipients` vérifie, **avant** toute écriture, qu'aucun couple de
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
| `decrypt_file_with_key` | contenu de fichier `.enc` arbitraire, contre une clé privée RSA fixe (seule expéditrice attendue) | lecture de l'en-tête v3 → recherche de `recipient_id` correspondant → `unwrap_key` → vérification de l'expéditeur, spécifique à ce crate. |
| `encrypt_decrypt_roundtrip` | contenu de fichier arbitraire, chiffré puis déchiffré pour un unique destinataire fixe | Propriété d'aller-retour (identité) sur des contenus que les tests unitaires n'énumèrent pas (octets nuls, tailles inhabituelles, motifs répétitifs). |
| `decrypt_paths_with_key` | contenu de fichier `.enc` arbitraire, contre une clé privée RSA fixe | Même surface que `decrypt_file_with_key`, mais via la voie archive multi-fichiers ; en pratique, la quasi-totalité des entrées aléatoires n'atteignent jamais `extract_archive` (échec d'authentification AEAD avant), voir la cible suivante pour ça. |
| `encrypt_decrypt_paths_roundtrip` | DEUX contenus de fichiers arbitraires (dérivés d'un seul buffer, découpé), chiffrés en une archive puis déchiffrés | Propriété d'aller-retour à travers une VRAIE archive multi-entrées, pas seulement l'AEAD d'un flux unique. |

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

Document à jour pour la version 2.0.0 (format v3 de `chiffre_aes_core`,
signature obligatoire de l'expéditeur). Les fichiers produits par les
versions 1.x (format v2) ne sont plus lisibles. Ce fichier fait foi sur la
convention réellement appliquée, indépendamment de l'implémentation.
