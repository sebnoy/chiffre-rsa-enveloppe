//! `chiffre-rsa-enveloppe` — orchestration multi-destinataires : produit
//! ou lit un fichier `.enc` complet en combinant `chiffre-rsa-core`
//! (scellement/descellement RSA-OAEP de la clé de contenu) et
//! `chiffre_aes_core` (format de fichier, chiffrement symétrique). Voir le
//! cahier des charges, Partie 2 §4.
//!
//! Ce crate ne connaît jamais de métadonnées ni de format JSON de
//! confiance (§6 du cahier des charges) — c'est `chiffre-rsa-keystore`
//! qui en aura la responsabilité, et l'application appelante qui décide,
//! après lecture d'un rapport de classification, en qui elle a confiance
//! avant de construire un `RecipientRef`.

use std::path::{Path, PathBuf};

use chiffre_aes_core::{ArchiveWarning, HeaderKeyRequirement, RawKey, Recipient};
use chiffre_rsa_core::{RsaKeyPair, RsaKeysError, RsaPublicKey};

#[derive(Debug, thiserror::Error)]
pub enum EnvelopeError {
    #[error("aucun destinataire fourni")]
    NoRecipients,
    #[error("ce fichier a été chiffré avec un mot de passe, pas pour une clé RSA")]
    NotEncryptedForKey,
    #[error(
        "aucune entrée de destinataire de ce fichier ne correspond à l'empreinte de cette clé privée"
    )]
    RecipientNotFound,
    #[error("erreur de format/chiffrement sous-jacent : {0}")]
    Format(#[from] chiffre_aes_core::FormatError),
    #[error("erreur RSA sous-jacente : {0}")]
    RsaKeys(#[from] RsaKeysError),
    #[error("erreur d'archivage sous-jacente : {0}")]
    Archive(#[from] chiffre_aes_core::ArchiveError),
    #[error("erreur système : {0}")]
    Io(#[from] std::io::Error),
    #[error("chemin sélectionné sans nom de fichier exploitable : {0}")]
    InvalidSelectedPath(String),
    #[error(
        "plusieurs chemins sélectionnés produiraient la même entrée « {0} » dans l'archive — \
         l'un écraserait l'autre silencieusement à l'extraction"
    )]
    DuplicateArchiveEntryName(String),
    #[error("« {0} » existe déjà dans le dossier de destination")]
    DestinationConflict(String),
}

/// Un destinataire pour [`encrypt_file_for_recipients`] : simple référence
/// vers une clé publique **déjà jugée de confiance par l'application
/// appelante**. Ce crate ne fait aucune vérification de confiance
/// lui-même — voir le cahier des charges §2 (tableau des interfaces) :
/// `chiffre-rsa-keystore` ne transmet jamais rien directement ici, c'est
/// toujours l'application qui fait le pont après une décision humaine.
pub struct RecipientRef<'a> {
    pub public_key: &'a RsaPublicKey,
}

/// Chiffre `input` pour l'ensemble des `recipients` fournis, en écrivant
/// un fichier `.enc` v2 (`key_source = 1`, destinataires externes) vers
/// `output`.
///
/// Génère une clé de contenu (CEK) aléatoire, la scelle une fois par
/// destinataire (RSA-OAEP, via `chiffre-rsa-core`), et délègue l'écriture
/// du fichier à `chiffre_aes_core::encrypt_file_with_raw_key` — un seul
/// destinataire n'est qu'un cas particulier de N, pas de chemin de code
/// séparé.
///
/// L'identifiant de destinataire (`recipient_id`) stocké dans le header
/// est l'empreinte SHA-256 de la clé publique
/// ([`RsaPublicKey::fingerprint`]) : c'est un choix de ce crate, pas de
/// `chiffre_aes_core` (qui traite cet identifiant comme un blob opaque) ni
/// de `chiffre-rsa-core` (qui calcule l'empreinte mais ne décide pas de
/// son usage). C'est ce même choix que [`decrypt_file_with_key`] suppose
/// pour retrouver la bonne entrée.
pub fn encrypt_file_for_recipients(
    input: &Path,
    output: &Path,
    recipients: &[RecipientRef],
) -> Result<(), EnvelopeError> {
    if recipients.is_empty() {
        return Err(EnvelopeError::NoRecipients);
    }

    let cek = RawKey::generate_random();

    let mut sealed_recipients = Vec::with_capacity(recipients.len());
    for recipient in recipients {
        let wrapped_key = recipient.public_key.wrap_key(&cek)?;
        let recipient_id = recipient.public_key.fingerprint().to_vec();
        sealed_recipients.push(Recipient {
            recipient_id,
            wrapped_key,
        });
    }

    chiffre_aes_core::encrypt_file_with_raw_key(input, output, cek, &sealed_recipients)?;
    Ok(())
}

/// Déchiffre `input` (fichier `.enc` v2, destinataires externes) avec
/// `key`, en écrivant le résultat vers `output`.
///
/// Inspecte d'abord le header (sans avoir besoin de `key` pour cela, voir
/// [`chiffre_aes_core::inspect_key_requirement`]) pour retrouver, parmi
/// les destinataires listés, celui dont `recipient_id` correspond à
/// l'empreinte de `key` — c'est le même appariement par empreinte que
/// [`encrypt_file_for_recipients`] a produit à l'écriture. Ne tente
/// **jamais** un descellement à l'aveugle sur une entrée qui ne
/// correspond pas : outre l'inefficacité, ça produirait une erreur RSA
/// (`UnwrapFailed`) moins informative que [`EnvelopeError::RecipientNotFound`].
pub fn decrypt_file_with_key(
    input: &Path,
    output: &Path,
    key: &RsaKeyPair,
) -> Result<(), EnvelopeError> {
    let requirement = chiffre_aes_core::inspect_key_requirement(input)?;

    let recipients = match requirement {
        HeaderKeyRequirement::Password => return Err(EnvelopeError::NotEncryptedForKey),
        HeaderKeyRequirement::ExternalKey { recipients } => recipients,
    };

    let our_fingerprint = key.public_key().fingerprint();
    let entry = recipients
        .iter()
        .find(|entry| entry.recipient_id.as_slice() == our_fingerprint.as_slice())
        .ok_or(EnvelopeError::RecipientNotFound)?;

    let cek = key.unwrap_key(&entry.wrapped_key)?;
    chiffre_aes_core::decrypt_file_with_raw_key(input, output, cek)?;
    Ok(())
}

/// Détermine le dossier dans lequel créer un fichier/dossier temporaire
/// pour une opération touchant `path` — le même dossier que `path`
/// lui-même quand c'est possible, pour garantir un `rename` atomique sur
/// le même système de fichiers ensuite (même principe que
/// `chiffre_aes_core::format::create_tmp_path`, qui n'est pas
/// accessible depuis ce crate — `pub(crate)` côté `chiffre_aes_core`).
fn sibling_dir_of(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

/// Chiffre `selected_paths` (fichiers et/ou dossiers) pour l'ensemble des
/// `recipients` fournis, en une archive multi-fichiers chiffrée — voir
/// `FORMAT.md` §6. Un seul fichier n'est qu'un cas particulier de
/// `selected_paths` à un seul élément : pas de fonction séparée pour ce
/// cas (contrairement à [`encrypt_file_for_recipients`], gardée telle
/// quelle pour l'usage simple mono-fichier sans dépendance à
/// `chiffre_aes_core::archive`).
///
/// L'archive intermédiaire (avant chiffrement) est construite dans un
/// fichier temporaire, sœur de `output` (même dossier), supprimé
/// automatiquement en fin d'opération — y compris en cas d'erreur — via
/// `tempfile::NamedTempFile`.
///
/// Retourne les avertissements non bloquants survenus lors de l'archivage
/// (éléments ignorés — liens symboliques, chemins non-UTF8, etc., voir
/// `chiffre_aes_core::archive`).
/// Vérifie qu'aucun couple de chemins dans `selected_paths` ne
/// produirait la même entrée dans l'archive (même
/// `Path::file_name()`) — sinon l'un écraserait l'autre silencieusement
/// à l'extraction, un comportement que `chiffre_aes_core::archive`
/// (construit pour un seul appelant cohérent, pas pour détecter les
/// doublons d'un appelant tiers) ne garantit pas.
///
/// Couvre, sans cas spécial, la collision entre un fichier de contenu
/// réel et une métadonnée réservée (`_expediteur.json`/
/// `_destinataires.json`, voir `FORMAT.md` §5.1) si l'application les
/// inclut toutes les deux sous le même nom par erreur — c'est un cas
/// particulier de cette vérification générale, pas un traitement séparé
/// des deux noms réservés.
fn check_no_duplicate_archive_entry_names(
    selected_paths: &[PathBuf],
) -> Result<(), EnvelopeError> {
    let mut seen = std::collections::HashSet::new();
    for path in selected_paths {
        let name = path
            .file_name()
            .ok_or_else(|| EnvelopeError::InvalidSelectedPath(path.display().to_string()))?
            .to_string_lossy()
            .into_owned();
        if !seen.insert(name.clone()) {
            return Err(EnvelopeError::DuplicateArchiveEntryName(name));
        }
    }
    Ok(())
}

pub fn encrypt_paths_for_recipients(
    selected_paths: &[PathBuf],
    output: &Path,
    recipients: &[RecipientRef],
) -> Result<Vec<ArchiveWarning>, EnvelopeError> {
    if recipients.is_empty() {
        return Err(EnvelopeError::NoRecipients);
    }
    check_no_duplicate_archive_entry_names(selected_paths)?;

    let tmp_archive = tempfile::NamedTempFile::new_in(sibling_dir_of(output))?;
    let warnings = {
        let mut writer = std::io::BufWriter::new(tmp_archive.as_file());
        let (_, warnings) = chiffre_aes_core::archive::build_archive(selected_paths, &mut writer)?;
        std::io::Write::flush(&mut writer)?;
        warnings
    };

    let cek = RawKey::generate_random();
    let mut sealed_recipients = Vec::with_capacity(recipients.len());
    for recipient in recipients {
        let wrapped_key = recipient.public_key.wrap_key(&cek)?;
        let recipient_id = recipient.public_key.fingerprint().to_vec();
        sealed_recipients.push(Recipient {
            recipient_id,
            wrapped_key,
        });
    }

    chiffre_aes_core::encrypt_file_with_raw_key(tmp_archive.path(), output, cek, &sealed_recipients)?;
    // `tmp_archive` est supprimé ici, à la sortie de portée (RAII) —
    // qu'on soit arrivés jusque là ou sortis plus tôt via `?`.
    Ok(warnings)
}

/// Déchiffre `input` (produit par [`encrypt_paths_for_recipients`]) et
/// restitue les fichiers/dossiers d'origine sous `destination_dir`.
///
/// Toujours désarchivé d'abord vers un dossier temporaire sœur de
/// `destination_dir`, jamais directement dedans — que `destination_dir`
/// existe déjà ou non. Si `destination_dir` n'existe pas encore : bascule
/// par un simple `rename` du dossier temporaire entier. Si
/// `destination_dir` existe déjà : déplacement entrée par entrée, en
/// deux passes — d'abord vérifier qu'aucune entrée ne collisionne avec
/// un élément déjà présent (auquel cas [`EnvelopeError::DestinationConflict`],
/// **rien n'est déplacé**), puis déplacer seulement si tout est propre.
/// Dans les deux cas, une erreur en cours d'extraction (avant la bascule)
/// ne laisse jamais `destination_dir` dans un état partiellement écrit.
pub fn decrypt_paths_with_key(
    input: &Path,
    destination_dir: &Path,
    key: &RsaKeyPair,
) -> Result<Vec<ArchiveWarning>, EnvelopeError> {
    let requirement = chiffre_aes_core::inspect_key_requirement(input)?;

    let recipients = match requirement {
        HeaderKeyRequirement::Password => return Err(EnvelopeError::NotEncryptedForKey),
        HeaderKeyRequirement::ExternalKey { recipients } => recipients,
    };

    let our_fingerprint = key.public_key().fingerprint();
    let entry = recipients
        .iter()
        .find(|entry| entry.recipient_id.as_slice() == our_fingerprint.as_slice())
        .ok_or(EnvelopeError::RecipientNotFound)?;
    let cek = key.unwrap_key(&entry.wrapped_key)?;

    let tmp_archive = tempfile::NamedTempFile::new_in(sibling_dir_of(input))?;
    chiffre_aes_core::decrypt_file_with_raw_key(input, tmp_archive.path(), cek)?;

    let dest_parent = sibling_dir_of(destination_dir);
    std::fs::create_dir_all(dest_parent)?;

    let tmp_extract_dir = tempfile::Builder::new()
        .prefix(".chiffre-rsa-enveloppe-extract-tmp-")
        .rand_bytes(16)
        .tempdir_in(dest_parent)?;

    let warnings = {
        let file = std::fs::File::open(tmp_archive.path())?;
        let mut reader = std::io::BufReader::new(file);
        chiffre_aes_core::archive::extract_archive(&mut reader, tmp_extract_dir.path())?
    };

    if destination_dir.exists() {
        move_entries_into_existing_dir(tmp_extract_dir.path(), destination_dir)?;
        // `tmp_extract_dir` est maintenant vide : nettoyage normal (Drop).
    } else {
        std::fs::rename(tmp_extract_dir.path(), destination_dir)?;
        // Le contenu a été déplacé vers destination_dir : on désarme la
        // suppression automatique via `keep()` plutôt que
        // `std::mem::forget` (voir FORMAT.md §5.3 — bug de fuite mémoire
        // déjà trouvé et corrigé sur exactement ce point).
        let _ = tmp_extract_dir.keep();
    }

    Ok(warnings)
}

/// Déplace chaque entrée de premier niveau de `source_dir` vers
/// `dest_dir` (qui existe déjà), en deux passes — voir la doc de
/// [`decrypt_paths_with_key`] pour la garantie que ça apporte.
fn move_entries_into_existing_dir(source_dir: &Path, dest_dir: &Path) -> Result<(), EnvelopeError> {
    let entries: Vec<std::fs::DirEntry> =
        std::fs::read_dir(source_dir)?.collect::<std::io::Result<Vec<_>>>()?;

    // Passe 1 : validation seule, aucune écriture.
    for entry in &entries {
        let target = dest_dir.join(entry.file_name());
        if target.exists() {
            return Err(EnvelopeError::DestinationConflict(
                target.display().to_string(),
            ));
        }
    }

    // Passe 2 : déplacement — plus aucune collision possible, sauf
    // modification concurrente de `dest_dir` par un autre processus
    // entre les deux passes (hors de portée de ce qu'une fonction
    // synchrone peut garantir seule, sans verrouillage externe).
    for entry in &entries {
        let target = dest_dir.join(entry.file_name());
        std::fs::rename(entry.path(), &target)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;
    use tempfile::tempdir;

    // Génération RSA-4096 coûteuse (plusieurs secondes) : trois clés
    // partagées entre tous les tests plutôt que régénérées à chaque fois.
    fn key_alice() -> &'static RsaKeyPair {
        static KEY: OnceLock<RsaKeyPair> = OnceLock::new();
        KEY.get_or_init(|| RsaKeyPair::generate().expect("génération clé Alice"))
    }

    fn key_bob() -> &'static RsaKeyPair {
        static KEY: OnceLock<RsaKeyPair> = OnceLock::new();
        KEY.get_or_init(|| RsaKeyPair::generate().expect("génération clé Bob"))
    }

    fn key_outsider() -> &'static RsaKeyPair {
        static KEY: OnceLock<RsaKeyPair> = OnceLock::new();
        KEY.get_or_init(|| RsaKeyPair::generate().expect("génération clé tierce (non destinataire)"))
    }

    #[test]
    fn roundtrip_single_recipient() {
        let dir = tempdir().expect("tempdir");
        let input = dir.path().join("plain.txt");
        let enc = dir.path().join("out.enc");
        let decrypted = dir.path().join("decrypted.txt");

        std::fs::write(&input, b"Contenu secret pour Alice uniquement.").unwrap();

        let alice_public = key_alice().public_key();
        encrypt_file_for_recipients(
            &input,
            &enc,
            &[RecipientRef {
                public_key: &alice_public,
            }],
        )
        .expect("chiffrement");

        decrypt_file_with_key(&enc, &decrypted, key_alice()).expect("déchiffrement");

        assert_eq!(
            std::fs::read(&input).unwrap(),
            std::fs::read(&decrypted).unwrap()
        );
    }

    #[test]
    fn roundtrip_multi_recipients_each_can_decrypt() {
        let dir = tempdir().expect("tempdir");
        let input = dir.path().join("plain.txt");
        let enc = dir.path().join("out.enc");

        std::fs::write(&input, b"Contenu partage entre Alice et Bob.").unwrap();

        let alice_public = key_alice().public_key();
        let bob_public = key_bob().public_key();

        encrypt_file_for_recipients(
            &input,
            &enc,
            &[
                RecipientRef {
                    public_key: &alice_public,
                },
                RecipientRef {
                    public_key: &bob_public,
                },
            ],
        )
        .expect("chiffrement multi-destinataires");

        let decrypted_alice = dir.path().join("decrypted_alice.txt");
        decrypt_file_with_key(&enc, &decrypted_alice, key_alice())
            .expect("déchiffrement par Alice");
        assert_eq!(
            std::fs::read(&input).unwrap(),
            std::fs::read(&decrypted_alice).unwrap()
        );

        let decrypted_bob = dir.path().join("decrypted_bob.txt");
        decrypt_file_with_key(&enc, &decrypted_bob, key_bob()).expect("déchiffrement par Bob");
        assert_eq!(
            std::fs::read(&input).unwrap(),
            std::fs::read(&decrypted_bob).unwrap()
        );
    }

    #[test]
    fn decrypt_with_non_recipient_key_fails_with_recipient_not_found() {
        let dir = tempdir().expect("tempdir");
        let input = dir.path().join("plain.txt");
        let enc = dir.path().join("out.enc");
        let decrypted = dir.path().join("decrypted.txt");

        std::fs::write(&input, b"Reserve a Alice.").unwrap();

        let alice_public = key_alice().public_key();
        encrypt_file_for_recipients(
            &input,
            &enc,
            &[RecipientRef {
                public_key: &alice_public,
            }],
        )
        .expect("chiffrement");

        let result = decrypt_file_with_key(&enc, &decrypted, key_outsider());
        assert!(matches!(result, Err(EnvelopeError::RecipientNotFound)));
    }

    #[test]
    fn encrypt_with_no_recipients_fails() {
        let dir = tempdir().expect("tempdir");
        let input = dir.path().join("plain.txt");
        let enc = dir.path().join("out.enc");
        std::fs::write(&input, b"peu importe").unwrap();

        let result = encrypt_file_for_recipients(&input, &enc, &[]);
        assert!(matches!(result, Err(EnvelopeError::NoRecipients)));
    }

    #[test]
    fn decrypt_password_based_file_with_rsa_key_fails_with_not_encrypted_for_key() {
        let dir = tempdir().expect("tempdir");
        let input = dir.path().join("plain.txt");
        let enc = dir.path().join("password.enc");
        let decrypted = dir.path().join("decrypted.txt");

        std::fs::write(&input, b"chiffre par mot de passe, pas par cle RSA").unwrap();

        // Paramètres Argon2 minimaux (bornes de policy de chiffre_aes_core)
        // pour que ce test reste rapide — la valeur de sécurité réelle
        // n'a aucune importance ici, seul le chemin `key_source = 0`
        // (mot de passe) est exercé.
        let password: chiffre_aes_core::Password =
            zeroize::Zeroizing::new("mot-de-passe-de-test".to_string());
        let params = chiffre_aes_core::Argon2Params {
            memory_kib: 8 * 1024,
            iterations: 1,
            parallelism: 1,
        };
        chiffre_aes_core::encrypt_file(&input, &enc, &password, params)
            .expect("chiffrement par mot de passe (v1)");

        let result = decrypt_file_with_key(&enc, &decrypted, key_alice());
        assert!(matches!(result, Err(EnvelopeError::NotEncryptedForKey)));
    }

    // --- encrypt_paths_for_recipients / decrypt_paths_with_key ---------

    #[test]
    fn paths_roundtrip_multiple_files_new_destination() {
        let dir = tempdir().expect("tempdir");
        let file_a = dir.path().join("a.txt");
        let file_b = dir.path().join("b.txt");
        std::fs::write(&file_a, b"contenu A").unwrap();
        std::fs::write(&file_b, b"contenu B, un peu plus long pour varier").unwrap();

        let enc = dir.path().join("archive.enc");
        let alice_public = key_alice().public_key();

        let warnings = encrypt_paths_for_recipients(
            &[file_a.clone(), file_b.clone()],
            &enc,
            &[RecipientRef {
                public_key: &alice_public,
            }],
        )
        .expect("chiffrement multi-fichiers");
        assert!(warnings.is_empty());

        // destination n'existe pas encore : exerce la branche
        // "bascule atomique via rename".
        let dest = dir.path().join("destination_absente");
        assert!(!dest.exists());

        let extract_warnings =
            decrypt_paths_with_key(&enc, &dest, key_alice()).expect("déchiffrement multi-fichiers");
        assert!(extract_warnings.is_empty());

        assert_eq!(std::fs::read(dest.join("a.txt")).unwrap(), b"contenu A");
        assert_eq!(
            std::fs::read(dest.join("b.txt")).unwrap(),
            b"contenu B, un peu plus long pour varier"
        );
    }

    #[test]
    fn paths_roundtrip_existing_destination() {
        let dir = tempdir().expect("tempdir");
        let file_a = dir.path().join("a.txt");
        std::fs::write(&file_a, b"contenu existant").unwrap();

        let enc = dir.path().join("archive.enc");
        let alice_public = key_alice().public_key();
        encrypt_paths_for_recipients(
            &[file_a],
            &enc,
            &[RecipientRef {
                public_key: &alice_public,
            }],
        )
        .expect("chiffrement");

        // destination existe déjà (avec un fichier sans rapport) :
        // exerce la branche non atomique documentée.
        let dest = dir.path().join("destination_existante");
        std::fs::create_dir_all(&dest).unwrap();
        std::fs::write(dest.join("deja_present.txt"), b"ne doit pas disparaitre").unwrap();

        decrypt_paths_with_key(&enc, &dest, key_alice()).expect("déchiffrement");

        assert_eq!(std::fs::read(dest.join("a.txt")).unwrap(), b"contenu existant");
        assert_eq!(
            std::fs::read(dest.join("deja_present.txt")).unwrap(),
            b"ne doit pas disparaitre"
        );
    }

    #[test]
    fn paths_multi_recipients_each_can_decrypt() {
        let dir = tempdir().expect("tempdir");
        let file_a = dir.path().join("a.txt");
        std::fs::write(&file_a, b"partage entre plusieurs destinataires").unwrap();

        let enc = dir.path().join("archive.enc");
        let alice_public = key_alice().public_key();
        let bob_public = key_bob().public_key();

        encrypt_paths_for_recipients(
            &[file_a],
            &enc,
            &[
                RecipientRef {
                    public_key: &alice_public,
                },
                RecipientRef {
                    public_key: &bob_public,
                },
            ],
        )
        .expect("chiffrement");

        let dest_alice = dir.path().join("dest_alice");
        decrypt_paths_with_key(&enc, &dest_alice, key_alice()).expect("déchiffrement Alice");
        assert_eq!(
            std::fs::read(dest_alice.join("a.txt")).unwrap(),
            b"partage entre plusieurs destinataires"
        );

        let dest_bob = dir.path().join("dest_bob");
        decrypt_paths_with_key(&enc, &dest_bob, key_bob()).expect("déchiffrement Bob");
        assert_eq!(
            std::fs::read(dest_bob.join("a.txt")).unwrap(),
            b"partage entre plusieurs destinataires"
        );
    }

    #[test]
    fn paths_encrypt_with_no_recipients_fails() {
        let dir = tempdir().expect("tempdir");
        let file_a = dir.path().join("a.txt");
        std::fs::write(&file_a, b"peu importe").unwrap();
        let enc = dir.path().join("archive.enc");

        let result = encrypt_paths_for_recipients(&[file_a], &enc, &[]);
        assert!(matches!(result, Err(EnvelopeError::NoRecipients)));
    }

    #[test]
    fn paths_decrypt_with_non_recipient_key_fails() {
        let dir = tempdir().expect("tempdir");
        let file_a = dir.path().join("a.txt");
        std::fs::write(&file_a, b"reserve a alice").unwrap();
        let enc = dir.path().join("archive.enc");

        let alice_public = key_alice().public_key();
        encrypt_paths_for_recipients(
            &[file_a],
            &enc,
            &[RecipientRef {
                public_key: &alice_public,
            }],
        )
        .expect("chiffrement");

        let dest = dir.path().join("dest");
        let result = decrypt_paths_with_key(&enc, &dest, key_outsider());
        assert!(matches!(result, Err(EnvelopeError::RecipientNotFound)));
    }

    #[test]
    fn paths_encrypt_rejects_duplicate_entry_names() {
        let dir = tempdir().expect("tempdir");
        // Deux chemins différents, mais même nom de fichier final —
        // collision d'entrée d'archive.
        let subdir_a = dir.path().join("sous_dossier_a");
        let subdir_b = dir.path().join("sous_dossier_b");
        std::fs::create_dir_all(&subdir_a).unwrap();
        std::fs::create_dir_all(&subdir_b).unwrap();
        let file_a = subdir_a.join("meme_nom.txt");
        let file_b = subdir_b.join("meme_nom.txt");
        std::fs::write(&file_a, b"contenu A").unwrap();
        std::fs::write(&file_b, b"contenu B").unwrap();

        let enc = dir.path().join("archive.enc");
        let alice_public = key_alice().public_key();

        let result = encrypt_paths_for_recipients(
            &[file_a, file_b],
            &enc,
            &[RecipientRef {
                public_key: &alice_public,
            }],
        );
        assert!(matches!(
            result,
            Err(EnvelopeError::DuplicateArchiveEntryName(name)) if name == "meme_nom.txt"
        ));
        // Rien n'a été écrit : la vérification a lieu avant tout accès
        // au fichier de sortie.
        assert!(!enc.exists());
    }

    #[test]
    fn paths_decrypt_into_existing_destination_detects_conflict_and_moves_nothing() {
        let dir = tempdir().expect("tempdir");
        let file_a = dir.path().join("a.txt");
        std::fs::write(&file_a, b"nouveau contenu").unwrap();

        let enc = dir.path().join("archive.enc");
        let alice_public = key_alice().public_key();
        encrypt_paths_for_recipients(
            &[file_a],
            &enc,
            &[RecipientRef {
                public_key: &alice_public,
            }],
        )
        .expect("chiffrement");

        // La destination existe déjà ET contient une entrée du même nom
        // que ce qui va être extrait ("a.txt") : collision volontaire.
        let dest = dir.path().join("destination_avec_collision");
        std::fs::create_dir_all(&dest).unwrap();
        std::fs::write(dest.join("a.txt"), b"ancien contenu a NE PAS ecraser").unwrap();
        std::fs::write(dest.join("autre_fichier.txt"), b"present avant").unwrap();

        let result = decrypt_paths_with_key(&enc, &dest, key_alice());
        assert!(matches!(result, Err(EnvelopeError::DestinationConflict(name)) if name.ends_with("a.txt")));

        // Aucune entrée n'a été déplacée (validation en deux passes) :
        // l'ancien contenu est intact, rien de nouveau n'est apparu.
        assert_eq!(
            std::fs::read(dest.join("a.txt")).unwrap(),
            b"ancien contenu a NE PAS ecraser"
        );
        assert_eq!(
            std::fs::read(dest.join("autre_fichier.txt")).unwrap(),
            b"present avant"
        );
    }

    #[test]
    fn paths_supports_reserved_metadata_filenames_alongside_real_content() {
        // Vérifie le mécanisme décrit dans FORMAT.md §6.1 : l'app peut
        // glisser _expediteur.json/_destinataires.json dans
        // selected_paths comme n'importe quel autre fichier — ce crate
        // ne leur fait subir aucun traitement spécial, il les archive
        // tels quels.
        let dir = tempdir().expect("tempdir");
        let content = dir.path().join("contenu.txt");
        let sender_doc = dir.path().join("_expediteur.json");
        std::fs::write(&content, b"le vrai contenu").unwrap();
        std::fs::write(&sender_doc, br#"{"identity":"alice"}"#).unwrap();

        let enc = dir.path().join("archive.enc");
        let alice_public = key_alice().public_key();
        encrypt_paths_for_recipients(
            &[content, sender_doc],
            &enc,
            &[RecipientRef {
                public_key: &alice_public,
            }],
        )
        .expect("chiffrement avec métadonnées");

        let dest = dir.path().join("dest");
        decrypt_paths_with_key(&enc, &dest, key_alice()).expect("déchiffrement");

        assert_eq!(std::fs::read(dest.join("contenu.txt")).unwrap(), b"le vrai contenu");
        assert_eq!(
            std::fs::read(dest.join("_expediteur.json")).unwrap(),
            br#"{"identity":"alice"}"#
        );
    }
}
