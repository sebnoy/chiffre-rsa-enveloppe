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
`chiffre_aes_core::FormatError` et `chiffre_rsa_core::RsaKeysError`, deux
distinctions propres à l'orchestration :

| Variante | Signification |
|---|---|
| `NoRecipients` | `encrypt_file_for_recipients` appelé avec un slice vide — rejeté *avant* d'appeler `chiffre_aes_core` (qui le rejetterait de toute façon via `FormatError::InvalidHeader`, mais avec un message moins spécifique). |
| `NotEncryptedForKey` | Le fichier inspecté attend un mot de passe, pas une clé RSA — probablement le mauvais outil de déchiffrement pour ce fichier (`chiffre_aes_core::decrypt_file` directement, avec un mot de passe). |
| `RecipientNotFound` | Aucune entrée du fichier ne correspond à l'empreinte de la clé privée fournie — cette clé n'est simplement pas un destinataire de ce fichier. |
| `Format(FormatError)` | Transparent, toute erreur remontée de `chiffre_aes_core` (fichier corrompu, tronqué, etc.). |
| `RsaKeys(RsaKeysError)` | Transparent, toute erreur remontée de `chiffre-rsa-core` lors du scellement/descellement. |

## 4. Ce qui n'est PAS spécifié ici

- Le nombre maximal de destinataires par fichier : c'est la politique de
  `chiffre_aes_core` (`MAX_RECIPIENTS = 64`) qui s'applique telle quelle,
  ce crate ne la duplique ni ne la resserre.
- La taille de `wrapped_key` : entièrement déterminée par
  `chiffre-rsa-core` (512 octets pour RSA-4096-OAEP-SHA256, voir son
  propre `FORMAT.md` §5) — ce crate la transmet telle quelle sans
  l'interpréter.

## 5. Fuzzing

Voir [fuzz/](./fuzz/) (`cargo-fuzz`, toolchain nightly).

| Cible | Entrée fuzzée | Ce qu'elle exerce |
|---|---|---|
| `decrypt_file_with_key` | contenu de fichier `.enc` arbitraire, contre une clé privée RSA fixe | `inspect_key_requirement` → recherche de `recipient_id` correspondant → `unwrap_key`, spécifique à ce crate. |
| `encrypt_decrypt_roundtrip` | contenu de fichier arbitraire, chiffré puis déchiffré pour un unique destinataire fixe | Propriété d'aller-retour (identité) sur des contenus que les tests unitaires n'énumèrent pas (octets nuls, tailles inhabituelles, motifs répétitifs). |

Les deux cibles utilisent une clé RSA-4096 **fixe** (même clé que
`chiffre-rsa-core/tests/vectors/fixed_test_key.pem`, copiée dans
`fuzz/fixed_key.pem`) — générer une paire à chaque itération serait
prohibitif sans rien apporter à la propriété recherchée.

`decrypt_file_with_key` n'a besoin d'aucune entrée valide pour être utile
(l'essentiel de la surface intéressante est déjà atteinte par le rejet
précoce d'un header malformé) ; `encrypt_decrypt_roundtrip`, à l'inverse,
est un test de propriété — un panic y indique un vrai bug de ce crate,
pas un comportement attendu face à une entrée hostile.

## 6. Statut

Document à jour à la date de rédaction (crate v0.1.0). Si un jour
`recipient_id` cesse d'être l'empreinte complète (par exemple pour des
raisons de taille de header avec un très grand nombre de destinataires),
ce fichier fait foi sur la convention réellement appliquée, indépendamment
de l'implémentation.