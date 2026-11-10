//! `chiffre-rsa-enveloppe` — orchestration multi-destinataires : produit
//! ou lit un fichier `.enc` complet (format v3 de `chiffre_aes_core`) en
//! combinant `chiffre-rsa-core` (scellement RSA-OAEP de la clé de contenu,
//! signature RSA-PSS de l'expéditeur) et `chiffre_aes_core` (format,
//! chiffrement symétrique, engagement de clé). Voir `FORMAT.md`.
//!
//! **Chaque fichier est signé par son expéditeur**, et le déchiffrement exige
//! la liste des expéditeurs attendus : un fichier signé par une autre clé est
//! refusé ([`EnvelopeError::SenderNotVerified`]) sans qu'aucun clair ne soit
//! livré.
//!
//! Ce crate ne décide jamais de la confiance : c'est l'application qui
//! choisit les clés publiques des destinataires ([`RecipientRef`]) et des
//! expéditeurs attendus, après sa propre vérification (par exemple avec
//! `chiffre-rsa-keystore`).

use std::cell::Cell;
use std::io::Read;
use std::path::{Path, PathBuf};

use chiffre_aes_core::{
    ArchiveError, ArchiveWarning, ExtractionLimits, FormatError, PipelineError,
    PresentedSenderVerifier, RawKey, Recipient, RecipientsInfo, SenderSigner, SenderVerifier,
};
use chiffre_rsa_core::{RsaKeyPair, RsaKeysError, RsaPublicKey};
use zeroize::Zeroizing;

/// Version de ce crate (`Cargo.toml`)
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Empreinte SHA-256 d'une clé publique ([`RsaPublicKey::fingerprint`]).
pub type Fingerprint = [u8; 32];

/// Préfixe du message signé en RSA-PSS : la même clé RSA peut signer
/// d'autres documents dans l'application (messages, répertoires) ; ce
/// préfixe empêche qu'une signature de fichier serve ailleurs, ou
/// l'inverse.
const SIGNATURE_DOMAIN: &[u8] = b"chiffre-rsa-enveloppe v2 signature de l'expediteur\0";

#[derive(Debug, thiserror::Error)]
pub enum EnvelopeError {
    #[error("aucun destinataire fourni")]
    NoRecipients,
    #[error("aucun expéditeur attendu fourni")]
    NoExpectedSenders,
    #[error("ce fichier a été chiffré avec un mot de passe, pas pour une clé RSA")]
    NotEncryptedForKey,
    #[error(
        "aucune entrée de destinataire de ce fichier ne correspond à l'empreinte de cette clé privée"
    )]
    RecipientNotFound,
    #[error(
        "expéditeur non vérifié : fichier signé par une clé non attendue, ou signature invalide"
    )]
    SenderNotVerified,
    #[error("erreur de format/chiffrement sous-jacent : {0}")]
    Format(#[from] FormatError),
    #[error("erreur RSA sous-jacente : {0}")]
    RsaKeys(#[from] RsaKeysError),
    #[error("erreur d'archivage sous-jacente : {0}")]
    Archive(#[from] ArchiveError),
    #[error("erreur système : {0}")]
    Io(#[from] std::io::Error),
    #[error("chemin sélectionné sans nom de fichier exploitable : {0}")]
    InvalidSelectedPath(String),
    #[error(
        "plusieurs chemins sélectionnés produiraient la même entrée « {0} » dans l'archive — \
         l'un écraserait l'autre silencieusement à l'extraction"
    )]
    DuplicateArchiveEntryName(String),
    #[error("{0}")]
    DestinationConflict(String),
}

/// Un destinataire : référence vers une clé publique **déjà jugée de
/// confiance par l'application appelante**.
pub struct RecipientRef<'a> {
    pub public_key: &'a RsaPublicKey,
}

/// Ce que l'en-tête d'un fichier révèle sans aucun secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvelopeInfo {
    /// Empreinte annoncée de la clé de l'expéditeur (non vérifiée tant que
    /// le fichier n'est pas déchiffré).
    pub sender_fingerprint: Vec<u8>,
    /// Empreintes des clés publiques des destinataires.
    pub recipient_fingerprints: Vec<Vec<u8>>,
}

// ============================================================================
// Signature et vérification de l'expéditeur
// ============================================================================

fn signed_message(transcript: &[u8; 32]) -> Vec<u8> {
    [SIGNATURE_DOMAIN, transcript.as_slice()].concat()
}

struct RsaSigner<'a>(&'a RsaKeyPair);

impl SenderSigner for RsaSigner<'_> {
    fn sender_id(&self) -> Vec<u8> {
        self.0.public_key().fingerprint().to_vec()
    }
    fn sign(&self, transcript: &[u8; 32]) -> Vec<u8> {
        self.0.sign(&signed_message(transcript))
    }
}

/// N'accepte qu'une clé de `expected`, et retient laquelle (ou le refus,
/// pour rapporter [`EnvelopeError::SenderNotVerified`] plutôt qu'une
/// corruption générique).
struct RsaVerifier<'a> {
    expected: &'a [RsaPublicKey],
    verified: Cell<Option<Fingerprint>>,
    refused: Cell<bool>,
}

impl<'a> RsaVerifier<'a> {
    fn new(expected: &'a [RsaPublicKey]) -> Result<Self, EnvelopeError> {
        if expected.is_empty() {
            return Err(EnvelopeError::NoExpectedSenders);
        }
        Ok(Self {
            expected,
            verified: Cell::new(None),
            refused: Cell::new(false),
        })
    }

    /// Traduit le résultat du format en expéditeur vérifié.
    fn outcome(&self, result: Result<(), FormatError>) -> Result<Fingerprint, EnvelopeError> {
        match result {
            Ok(()) => self.verified.get().ok_or(EnvelopeError::SenderNotVerified),
            Err(FormatError::Corrupted) if self.refused.get() => {
                Err(EnvelopeError::SenderNotVerified)
            }
            Err(e) => Err(e.into()),
        }
    }
}

impl SenderVerifier for RsaVerifier<'_> {
    fn verify(&self, sender_id: &[u8], transcript: &[u8; 32], signature: &[u8]) -> bool {
        let accepted = self.expected.iter().find_map(|key| {
            let fingerprint = key.fingerprint();
            (fingerprint.as_slice() == sender_id
                && key.verify(&signed_message(transcript), signature).is_ok())
            .then_some(fingerprint)
        });
        self.verified.set(accepted);
        self.refused.set(accepted.is_none());
        accepted.is_some()
    }
}

// ============================================================================
// Clé de contenu : scellement et descellement
// ============================================================================

/// Génère une clé de contenu et la scelle (RSA-OAEP) pour chaque
/// destinataire, identifié par l'empreinte de sa clé publique.
fn seal(recipients: &[RecipientRef]) -> Result<(RawKey, Vec<Recipient>), EnvelopeError> {
    if recipients.is_empty() {
        return Err(EnvelopeError::NoRecipients);
    }
    let cek = RawKey::generate_random();
    let sealed = recipients
        .iter()
        .map(|r| {
            Ok(Recipient {
                recipient_id: r.public_key.fingerprint().to_vec(),
                wrapped_key: r.public_key.wrap_key(&cek)?,
            })
        })
        .collect::<Result<Vec<_>, EnvelopeError>>()?;
    Ok((cek, sealed))
}

/// Retrouve l'entrée qui correspond à `key` (par empreinte, jamais à
/// l'aveugle) et descelle la clé de contenu.
fn unseal(info: &RecipientsInfo, key: &RsaKeyPair) -> Result<RawKey, EnvelopeError> {
    let fingerprint = key.public_key().fingerprint();
    let entry = info
        .recipients
        .iter()
        .find(|r| r.recipient_id.as_slice() == fingerprint.as_slice())
        .ok_or(EnvelopeError::RecipientNotFound)?;
    Ok(key.unwrap_key(&entry.wrapped_key)?)
}

/// Un fichier v1 (mot de passe) est signalé comme tel plutôt que comme un
/// en-tête invalide.
fn reject_password_container(start: &[u8]) -> Result<(), EnvelopeError> {
    if start.len() >= 5 && &start[..4] == b"ENC1" && start[4] == 1 {
        return Err(EnvelopeError::NotEncryptedForKey);
    }
    Ok(())
}

fn recipients_of_file(input: &Path) -> Result<RecipientsInfo, EnvelopeError> {
    let mut start = Vec::with_capacity(5);
    std::fs::File::open(input)?
        .take(5)
        .read_to_end(&mut start)?;
    reject_password_container(&start)?;
    Ok(chiffre_aes_core::inspect_recipients(input)?)
}

fn recipients_of_bytes(container: &[u8]) -> Result<RecipientsInfo, EnvelopeError> {
    reject_password_container(container)?;
    Ok(chiffre_aes_core::inspect_recipients_bytes(container)?)
}

fn envelope_info(info: RecipientsInfo) -> EnvelopeInfo {
    EnvelopeInfo {
        sender_fingerprint: info.sender_id,
        recipient_fingerprints: info
            .recipients
            .into_iter()
            .map(|r| r.recipient_id)
            .collect(),
    }
}

/// Lit l'en-tête d'un fichier sans secret : expéditeur annoncé et
/// destinataires.
pub fn inspect_file(input: &Path) -> Result<EnvelopeInfo, EnvelopeError> {
    Ok(envelope_info(recipients_of_file(input)?))
}

/// Identique à [`inspect_file`], pour un conteneur en mémoire.
pub fn inspect_bytes(container: &[u8]) -> Result<EnvelopeInfo, EnvelopeError> {
    Ok(envelope_info(recipients_of_bytes(container)?))
}

// ============================================================================
// Fichiers
// ============================================================================

/// Chiffre `input` pour `recipients`, signé par `sender`, vers `output`.
pub fn encrypt_file_for_recipients(
    input: &Path,
    output: &Path,
    recipients: &[RecipientRef],
    sender: &RsaKeyPair,
) -> Result<(), EnvelopeError> {
    let (cek, sealed) = seal(recipients)?;
    chiffre_aes_core::encrypt_file_for_recipients(input, output, cek, &sealed, &RsaSigner(sender))?;
    Ok(())
}

/// Déchiffre `input` avec `key` vers `output`, à condition qu'il soit signé
/// par l'une des clés de `expected_senders`. Renvoie l'empreinte de
/// l'expéditeur vérifié. Rien n'est écrit à `output` en cas de refus.
pub fn decrypt_file_with_key(
    input: &Path,
    output: &Path,
    key: &RsaKeyPair,
    expected_senders: &[RsaPublicKey],
) -> Result<Fingerprint, EnvelopeError> {
    let verifier = RsaVerifier::new(expected_senders)?;
    let cek = unseal(&recipients_of_file(input)?, key)?;
    verifier.outcome(chiffre_aes_core::decrypt_file_from_sender(
        input, output, cek, &verifier,
    ))
}

// ============================================================================
// Mémoire : aucun fichier temporaire, aucun clair sur disque
// ============================================================================

/// Chiffre `plaintext` en mémoire pour `recipients`, signé par `sender`.
pub fn encrypt_bytes_for_recipients(
    plaintext: &[u8],
    recipients: &[RecipientRef],
    sender: &RsaKeyPair,
) -> Result<Vec<u8>, EnvelopeError> {
    let (cek, sealed) = seal(recipients)?;
    Ok(chiffre_aes_core::encrypt_bytes_for_recipients(
        plaintext,
        cek,
        &sealed,
        &RsaSigner(sender),
    )?)
}

/// Déchiffre un conteneur en mémoire, à condition qu'il soit signé par l'une
/// des clés de `expected_senders`. Renvoie le clair (effacé à sa
/// destruction) et l'empreinte de l'expéditeur vérifié.
pub fn decrypt_bytes_with_key(
    container: &[u8],
    key: &RsaKeyPair,
    expected_senders: &[RsaPublicKey],
) -> Result<(Zeroizing<Vec<u8>>, Fingerprint), EnvelopeError> {
    let verifier = RsaVerifier::new(expected_senders)?;
    let cek = unseal(&recipients_of_bytes(container)?, key)?;
    let mut plaintext = None;
    let sender = verifier.outcome(
        chiffre_aes_core::decrypt_bytes_from_sender(container, cek, &verifier)
            .map(|p| plaintext = Some(p)),
    )?;
    Ok((plaintext.expect("rempli en cas de succès"), sender))
}

/// Vérificateur d'un expéditeur présenté dans le contenu : `present` y trouve
/// la clé candidate ; elle doit correspondre à `sender_id` et la signature
/// doit être valide pour elle.
struct PresentedRsaVerifier<F> {
    present: F,
    verified: Cell<Option<Fingerprint>>,
    refused: Cell<bool>,
}

impl<F: Fn(&[u8]) -> Option<RsaPublicKey>> PresentedSenderVerifier for PresentedRsaVerifier<F> {
    fn verify(
        &self,
        plaintext: &[u8],
        sender_id: &[u8],
        transcript: &[u8; 32],
        signature: &[u8],
    ) -> bool {
        let accepted = (self.present)(plaintext).and_then(|key| {
            let fingerprint = key.fingerprint();
            (fingerprint.as_slice() == sender_id
                && key.verify(&signed_message(transcript), signature).is_ok())
            .then_some(fingerprint)
        });
        self.verified.set(accepted);
        self.refused.set(accepted.is_none());
        accepted.is_some()
    }
}

/// Déchiffre en mémoire le message d'un expéditeur **qui se présente dans le
/// contenu** (par exemple le premier message d'un contact, portant son
/// certificat), quand sa clé n'est pas encore connue.
///
/// `present` reçoit le contenu déchiffré, **authentifié par la clé de contenu
/// mais pas encore par l'expéditeur** (n'importe quel destinataire aurait pu
/// l'écrire). Elle doit renvoyer la clé de l'expéditeur **seulement après en
/// avoir établi l'autorité par un moyen indépendant** — typiquement : le
/// certificat joint est signé par une clé admin déjà figée par
/// l'application — et `None` sinon. Le message est ensuite accepté seulement
/// si l'expéditeur annoncé dans l'en-tête est cette clé et si la signature est
/// valide pour elle ; sinon [`EnvelopeError::SenderNotVerified`], et le
/// contenu est effacé sans être rendu.
pub fn decrypt_bytes_with_key_from_presented_sender<F>(
    container: &[u8],
    key: &RsaKeyPair,
    present: F,
) -> Result<(Zeroizing<Vec<u8>>, Fingerprint), EnvelopeError>
where
    F: Fn(&[u8]) -> Option<RsaPublicKey>,
{
    let cek = unseal(&recipients_of_bytes(container)?, key)?;
    let verifier = PresentedRsaVerifier {
        present,
        verified: Cell::new(None),
        refused: Cell::new(false),
    };
    match chiffre_aes_core::decrypt_bytes_from_presented_sender(container, cek, &verifier) {
        Ok(plaintext) => {
            let sender = verifier
                .verified
                .get()
                .ok_or(EnvelopeError::SenderNotVerified)?;
            Ok((plaintext, sender))
        }
        Err(FormatError::Corrupted) if verifier.refused.get() => {
            Err(EnvelopeError::SenderNotVerified)
        }
        Err(e) => Err(e.into()),
    }
}

// ============================================================================
// Archives multi-fichiers
// ============================================================================

/// Deux chemins de même nom produiraient la même entrée d'archive.
/// `chiffre_aes_core` le refuse aussi ; ce contrôle préalable donne une
/// erreur précise, avant tout accès au fichier de sortie.
fn check_no_duplicate_archive_entry_names(selected_paths: &[PathBuf]) -> Result<(), EnvelopeError> {
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

fn pipeline_error(e: PipelineError) -> EnvelopeError {
    match e {
        PipelineError::Format(f) => f.into(),
        PipelineError::Archive(ArchiveError::Io(io))
            if io.kind() == std::io::ErrorKind::AlreadyExists =>
        {
            EnvelopeError::DestinationConflict(io.to_string())
        }
        PipelineError::Archive(a) => a.into(),
    }
}

/// Chiffre `selected_paths` (fichiers et/ou dossiers) pour `recipients`,
/// signé par `sender`, en une archive. L'archive intermédiaire est chiffrée
/// sous une clé éphémère (aucun clair sur disque) et la sortie est écrite de
/// façon durable (voir `chiffre_aes_core::encrypt_paths_for_recipients`).
pub fn encrypt_paths_for_recipients(
    selected_paths: &[PathBuf],
    output: &Path,
    recipients: &[RecipientRef],
    sender: &RsaKeyPair,
) -> Result<Vec<ArchiveWarning>, EnvelopeError> {
    check_no_duplicate_archive_entry_names(selected_paths)?;
    let (cek, sealed) = seal(recipients)?;
    chiffre_aes_core::encrypt_paths_for_recipients(
        selected_paths,
        output,
        cek,
        &sealed,
        &RsaSigner(sender),
        &mut |_| true,
    )
    .map_err(pipeline_error)
}

/// Déchiffre une archive produite par [`encrypt_paths_for_recipients`] vers
/// `destination_dir`, à condition qu'elle soit signée par l'une des clés de
/// `expected_senders`. Rien n'est extrait avant la vérification complète ;
/// un élément déjà présent à la destination fait échouer l'opération sans
/// rien déplacer ([`EnvelopeError::DestinationConflict`]).
pub fn decrypt_paths_with_key(
    input: &Path,
    destination_dir: &Path,
    key: &RsaKeyPair,
    expected_senders: &[RsaPublicKey],
) -> Result<(Vec<ArchiveWarning>, Fingerprint), EnvelopeError> {
    let verifier = RsaVerifier::new(expected_senders)?;
    let cek = unseal(&recipients_of_file(input)?, key)?;
    let result = chiffre_aes_core::decrypt_to_dir_from_sender(
        input,
        destination_dir,
        cek,
        &verifier,
        ExtractionLimits::default(),
        &mut |_| true,
    );
    match result {
        Ok(warnings) => Ok((warnings, verifier.outcome(Ok(()))?)),
        Err(PipelineError::Format(f)) => Err(verifier.outcome(Err(f)).unwrap_err()),
        Err(e) => Err(pipeline_error(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::OnceLock;
    use tempfile::tempdir;

    // Génération RSA-4096 coûteuse (plusieurs secondes) : clés partagées
    // entre tous les tests plutôt que régénérées à chaque fois.
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
        KEY.get_or_init(|| RsaKeyPair::generate().expect("génération clé tierce"))
    }

    /// Alice écrit, Alice est seule destinataire et seule expéditrice
    /// attendue : le cas le plus simple.
    fn alice_only() -> (RsaPublicKey, Vec<RsaPublicKey>) {
        (key_alice().public_key(), vec![key_alice().public_key()])
    }

    #[test]
    fn roundtrip_single_recipient_returns_verified_sender() {
        let dir = tempdir().unwrap();
        let (input, enc, out) = (
            dir.path().join("plain.txt"),
            dir.path().join("out.enc"),
            dir.path().join("decrypted.txt"),
        );
        std::fs::write(&input, b"Contenu secret pour Alice uniquement.").unwrap();
        let (alice, expected) = alice_only();
        encrypt_file_for_recipients(
            &input,
            &enc,
            &[RecipientRef { public_key: &alice }],
            key_alice(),
        )
        .unwrap();

        let sender = decrypt_file_with_key(&enc, &out, key_alice(), &expected).unwrap();
        assert_eq!(sender, alice.fingerprint());
        assert_eq!(std::fs::read(&input).unwrap(), std::fs::read(&out).unwrap());
    }

    #[test]
    fn roundtrip_multi_recipients_each_can_decrypt() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("plain.txt");
        let enc = dir.path().join("out.enc");
        std::fs::write(&input, b"Contenu partage entre Alice et Bob.").unwrap();
        let (alice, bob) = (key_alice().public_key(), key_bob().public_key());
        encrypt_file_for_recipients(
            &input,
            &enc,
            &[
                RecipientRef { public_key: &alice },
                RecipientRef { public_key: &bob },
            ],
            key_alice(),
        )
        .unwrap();

        for (name, key) in [("alice", key_alice()), ("bob", key_bob())] {
            let out = dir.path().join(name);
            decrypt_file_with_key(&enc, &out, key, std::slice::from_ref(&alice)).unwrap();
            assert_eq!(std::fs::read(&input).unwrap(), std::fs::read(&out).unwrap());
        }
    }

    #[test]
    fn decrypt_with_non_recipient_key_fails_with_recipient_not_found() {
        let dir = tempdir().unwrap();
        let (input, enc) = (dir.path().join("plain.txt"), dir.path().join("out.enc"));
        std::fs::write(&input, b"Reserve a Alice.").unwrap();
        let (alice, expected) = alice_only();
        encrypt_file_for_recipients(
            &input,
            &enc,
            &[RecipientRef { public_key: &alice }],
            key_alice(),
        )
        .unwrap();
        let result = decrypt_file_with_key(&enc, &dir.path().join("o"), key_outsider(), &expected);
        assert!(matches!(result, Err(EnvelopeError::RecipientNotFound)));
    }

    #[test]
    fn encrypt_with_no_recipients_fails() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("plain.txt");
        std::fs::write(&input, b"peu importe").unwrap();
        let result =
            encrypt_file_for_recipients(&input, &dir.path().join("o.enc"), &[], key_alice());
        assert!(matches!(result, Err(EnvelopeError::NoRecipients)));
    }

    #[test]
    fn decrypt_without_expected_senders_fails() {
        let result = decrypt_bytes_with_key(b"", key_alice(), &[]);
        assert!(matches!(result, Err(EnvelopeError::NoExpectedSenders)));
    }

    #[test]
    fn decrypt_password_based_file_with_rsa_key_fails_with_not_encrypted_for_key() {
        let dir = tempdir().unwrap();
        let (input, enc) = (
            dir.path().join("plain.txt"),
            dir.path().join("password.enc"),
        );
        std::fs::write(&input, b"chiffre par mot de passe, pas par cle RSA").unwrap();
        let password: chiffre_aes_core::Password =
            Zeroizing::new("mot-de-passe-de-test".to_string());
        let params = chiffre_aes_core::Argon2Params {
            memory_kib: 8 * 1024,
            iterations: 1,
            parallelism: 1,
        };
        chiffre_aes_core::encrypt_file(&input, &enc, &password, params).unwrap();

        let (_, expected) = alice_only();
        let result = decrypt_file_with_key(&enc, &dir.path().join("o"), key_alice(), &expected);
        assert!(matches!(result, Err(EnvelopeError::NotEncryptedForKey)));
        let bytes = std::fs::read(&enc).unwrap();
        let result = decrypt_bytes_with_key(&bytes, key_alice(), &expected);
        assert!(matches!(result, Err(EnvelopeError::NotEncryptedForKey)));
    }

    // --- Expéditeur ------------------------------------------------------------

    #[test]
    fn file_signed_by_unexpected_sender_is_refused_without_output() {
        // Bob connaît la clé publique d'Alice et lui écrit en son propre nom ;
        // Alice n'attend qu'elle-même.
        let dir = tempdir().unwrap();
        let (input, enc, out) = (
            dir.path().join("plain.txt"),
            dir.path().join("out.enc"),
            dir.path().join("o"),
        );
        std::fs::write(&input, b"faux message").unwrap();
        let (alice, expected) = alice_only();
        encrypt_file_for_recipients(
            &input,
            &enc,
            &[RecipientRef { public_key: &alice }],
            key_bob(),
        )
        .unwrap();

        let result = decrypt_file_with_key(&enc, &out, key_alice(), &expected);
        assert!(
            matches!(result, Err(EnvelopeError::SenderNotVerified)),
            "{result:?}"
        );
        assert!(!out.exists());
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            2,
            "aucun temporaire"
        );
    }

    /// Annonce l'empreinte d'Alice mais signe avec la clé de Bob.
    struct Usurpateur;
    impl SenderSigner for Usurpateur {
        fn sender_id(&self) -> Vec<u8> {
            key_alice().public_key().fingerprint().to_vec()
        }
        fn sign(&self, transcript: &[u8; 32]) -> Vec<u8> {
            key_bob().sign(&signed_message(transcript))
        }
    }

    /// Signe avec la bonne clé, mais sans le préfixe de ce crate : une
    /// signature RSA-PSS de la même clé faite pour un autre usage.
    struct SansDomaine;
    impl SenderSigner for SansDomaine {
        fn sender_id(&self) -> Vec<u8> {
            key_alice().public_key().fingerprint().to_vec()
        }
        fn sign(&self, transcript: &[u8; 32]) -> Vec<u8> {
            key_alice().sign(transcript)
        }
    }

    #[test]
    fn spoofed_sender_or_foreign_signature_is_refused() {
        let alice = key_alice().public_key();
        let expected = vec![alice.clone()];
        for signer in [&Usurpateur as &dyn SenderSigner, &SansDomaine] {
            let cek = RawKey::generate_random();
            let sealed = vec![Recipient {
                recipient_id: alice.fingerprint().to_vec(),
                wrapped_key: alice.wrap_key(&cek).unwrap(),
            }];
            let container =
                chiffre_aes_core::encrypt_bytes_for_recipients(b"x", cek, &sealed, signer).unwrap();
            let result = decrypt_bytes_with_key(&container, key_alice(), &expected);
            assert!(
                matches!(result, Err(EnvelopeError::SenderNotVerified)),
                "{result:?}"
            );
        }
    }

    #[test]
    fn several_expected_senders_identifies_the_actual_one() {
        let alice = key_alice().public_key();
        let container = encrypt_bytes_for_recipients(
            b"bonjour",
            &[RecipientRef { public_key: &alice }],
            key_bob(),
        )
        .unwrap();
        let expected = vec![key_outsider().public_key(), key_bob().public_key()];
        let (plaintext, sender) =
            decrypt_bytes_with_key(&container, key_alice(), &expected).unwrap();
        assert_eq!(&plaintext[..], b"bonjour");
        assert_eq!(sender, key_bob().public_key().fingerprint());
    }

    #[test]
    fn inspection_reveals_sender_and_recipients_without_secret() {
        let (alice, bob) = (key_alice().public_key(), key_bob().public_key());
        let container = encrypt_bytes_for_recipients(
            b"x",
            &[
                RecipientRef { public_key: &alice },
                RecipientRef { public_key: &bob },
            ],
            key_bob(),
        )
        .unwrap();
        let info = inspect_bytes(&container).unwrap();
        assert_eq!(info.sender_fingerprint, bob.fingerprint().to_vec());
        assert_eq!(
            info.recipient_fingerprints,
            vec![alice.fingerprint().to_vec(), bob.fingerprint().to_vec()]
        );
    }

    // --- Expéditeur présenté dans le contenu ---------------------------------

    /// Contenu de test : « <empreinte hex de l'expéditeur>\n<texte> ».
    fn presentation(sender: &RsaPublicKey, texte: &str) -> Vec<u8> {
        let hex: String = sender
            .fingerprint()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        format!("{hex}\n{texte}").into_bytes()
    }

    /// « Certificats » de confiance : l'application ne connaît que Bob.
    fn trouve_bob(plaintext: &[u8]) -> Option<RsaPublicKey> {
        let bob = key_bob().public_key();
        let annonce = plaintext.split(|b| *b == b'\n').next()?;
        (annonce == &presentation(&bob, "")[..64]).then_some(bob)
    }

    #[test]
    fn presented_sender_is_accepted_and_identified() {
        let alice = key_alice().public_key();
        let bob = key_bob().public_key();
        let container = encrypt_bytes_for_recipients(
            &presentation(&bob, "premier message"),
            &[RecipientRef { public_key: &alice }],
            key_bob(),
        )
        .unwrap();
        let (clair, sender) =
            decrypt_bytes_with_key_from_presented_sender(&container, key_alice(), trouve_bob)
                .unwrap();
        assert_eq!(sender, bob.fingerprint());
        assert!(clair.ends_with(b"premier message"));
    }

    #[test]
    fn presented_sender_impersonation_is_refused() {
        // Le tiers se présente comme Bob mais signe avec sa propre clé.
        let alice = key_alice().public_key();
        let bob = key_bob().public_key();
        let container = encrypt_bytes_for_recipients(
            &presentation(&bob, "faux"),
            &[RecipientRef { public_key: &alice }],
            key_outsider(),
        )
        .unwrap();
        let result =
            decrypt_bytes_with_key_from_presented_sender(&container, key_alice(), trouve_bob);
        assert!(
            matches!(result, Err(EnvelopeError::SenderNotVerified)),
            "{result:?}"
        );
        // Le tiers se présente sous son propre nom : aucune autorité établie.
        let tiers = key_outsider().public_key();
        let container = encrypt_bytes_for_recipients(
            &presentation(&tiers, "x"),
            &[RecipientRef { public_key: &alice }],
            key_outsider(),
        )
        .unwrap();
        let result =
            decrypt_bytes_with_key_from_presented_sender(&container, key_alice(), trouve_bob);
        assert!(
            matches!(result, Err(EnvelopeError::SenderNotVerified)),
            "{result:?}"
        );
    }

    // --- Archives ------------------------------------------------------------

    fn encrypt_paths_for_alice(paths: &[PathBuf], enc: &Path) -> Vec<ArchiveWarning> {
        let alice = key_alice().public_key();
        encrypt_paths_for_recipients(
            paths,
            enc,
            &[RecipientRef { public_key: &alice }],
            key_alice(),
        )
        .unwrap()
    }

    #[test]
    fn paths_roundtrip_multiple_files_new_destination() {
        let dir = tempdir().unwrap();
        let (file_a, file_b) = (dir.path().join("a.txt"), dir.path().join("b.txt"));
        std::fs::write(&file_a, b"contenu A").unwrap();
        std::fs::write(&file_b, b"contenu B, un peu plus long pour varier").unwrap();
        let enc = dir.path().join("archive.enc");
        assert!(encrypt_paths_for_alice(&[file_a, file_b], &enc).is_empty());

        let dest = dir.path().join("destination_absente");
        let (_, expected) = alice_only();
        let (warnings, sender) =
            decrypt_paths_with_key(&enc, &dest, key_alice(), &expected).unwrap();
        assert!(warnings.is_empty());
        assert_eq!(sender, key_alice().public_key().fingerprint());
        assert_eq!(std::fs::read(dest.join("a.txt")).unwrap(), b"contenu A");
        assert_eq!(
            std::fs::read(dest.join("b.txt")).unwrap(),
            b"contenu B, un peu plus long pour varier"
        );
    }

    #[test]
    fn paths_roundtrip_existing_destination() {
        let dir = tempdir().unwrap();
        let file_a = dir.path().join("a.txt");
        std::fs::write(&file_a, b"contenu existant").unwrap();
        let enc = dir.path().join("archive.enc");
        encrypt_paths_for_alice(&[file_a], &enc);

        let dest = dir.path().join("destination_existante");
        std::fs::create_dir_all(&dest).unwrap();
        std::fs::write(dest.join("deja_present.txt"), b"ne doit pas disparaitre").unwrap();
        let (_, expected) = alice_only();
        decrypt_paths_with_key(&enc, &dest, key_alice(), &expected).unwrap();
        assert_eq!(
            std::fs::read(dest.join("a.txt")).unwrap(),
            b"contenu existant"
        );
        assert_eq!(
            std::fs::read(dest.join("deja_present.txt")).unwrap(),
            b"ne doit pas disparaitre"
        );
    }

    #[test]
    fn paths_signed_by_unexpected_sender_extracts_nothing() {
        let dir = tempdir().unwrap();
        let file_a = dir.path().join("a.txt");
        std::fs::write(&file_a, b"x").unwrap();
        let enc = dir.path().join("archive.enc");
        let alice = key_alice().public_key();
        encrypt_paths_for_recipients(
            &[file_a],
            &enc,
            &[RecipientRef { public_key: &alice }],
            key_outsider(),
        )
        .unwrap();

        let dest = dir.path().join("dest");
        let (_, expected) = alice_only();
        let result = decrypt_paths_with_key(&enc, &dest, key_alice(), &expected);
        assert!(
            matches!(result, Err(EnvelopeError::SenderNotVerified)),
            "{result:?}"
        );
        assert!(!dest.exists());
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            2,
            "aucun temporaire"
        );
    }

    #[test]
    fn paths_encrypt_with_no_recipients_fails() {
        let dir = tempdir().unwrap();
        let file_a = dir.path().join("a.txt");
        std::fs::write(&file_a, b"peu importe").unwrap();
        let result =
            encrypt_paths_for_recipients(&[file_a], &dir.path().join("a.enc"), &[], key_alice());
        assert!(matches!(result, Err(EnvelopeError::NoRecipients)));
    }

    #[test]
    fn paths_decrypt_with_non_recipient_key_fails() {
        let dir = tempdir().unwrap();
        let file_a = dir.path().join("a.txt");
        std::fs::write(&file_a, b"reserve a alice").unwrap();
        let enc = dir.path().join("archive.enc");
        encrypt_paths_for_alice(&[file_a], &enc);
        let (_, expected) = alice_only();
        let result =
            decrypt_paths_with_key(&enc, &dir.path().join("dest"), key_outsider(), &expected);
        assert!(matches!(result, Err(EnvelopeError::RecipientNotFound)));
    }

    #[test]
    fn paths_encrypt_rejects_duplicate_entry_names() {
        let dir = tempdir().unwrap();
        let (subdir_a, subdir_b) = (dir.path().join("a"), dir.path().join("b"));
        std::fs::create_dir_all(&subdir_a).unwrap();
        std::fs::create_dir_all(&subdir_b).unwrap();
        let (file_a, file_b) = (subdir_a.join("meme_nom.txt"), subdir_b.join("meme_nom.txt"));
        std::fs::write(&file_a, b"contenu A").unwrap();
        std::fs::write(&file_b, b"contenu B").unwrap();
        let enc = dir.path().join("archive.enc");
        let alice = key_alice().public_key();
        let result = encrypt_paths_for_recipients(
            &[file_a, file_b],
            &enc,
            &[RecipientRef { public_key: &alice }],
            key_alice(),
        );
        assert!(matches!(
            result,
            Err(EnvelopeError::DuplicateArchiveEntryName(name)) if name == "meme_nom.txt"
        ));
        assert!(!enc.exists());
    }

    #[test]
    fn paths_decrypt_into_existing_destination_detects_conflict_and_moves_nothing() {
        let dir = tempdir().unwrap();
        let file_a = dir.path().join("a.txt");
        std::fs::write(&file_a, b"nouveau contenu").unwrap();
        let enc = dir.path().join("archive.enc");
        encrypt_paths_for_alice(&[file_a], &enc);

        let dest = dir.path().join("destination_avec_collision");
        std::fs::create_dir_all(&dest).unwrap();
        std::fs::write(dest.join("a.txt"), b"ancien contenu a NE PAS ecraser").unwrap();
        std::fs::write(dest.join("autre_fichier.txt"), b"present avant").unwrap();

        let (_, expected) = alice_only();
        let result = decrypt_paths_with_key(&enc, &dest, key_alice(), &expected);
        assert!(
            matches!(&result, Err(EnvelopeError::DestinationConflict(m)) if m.contains("a.txt")),
            "{result:?}"
        );
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
        // FORMAT.md §5.1 : l'application peut glisser _expediteur.json /
        // _destinataires.json parmi les chemins ; ils sont archivés tels quels.
        let dir = tempdir().unwrap();
        let content = dir.path().join("contenu.txt");
        let sender_doc = dir.path().join("_expediteur.json");
        std::fs::write(&content, b"le vrai contenu").unwrap();
        std::fs::write(&sender_doc, br#"{"identity":"alice"}"#).unwrap();
        let enc = dir.path().join("archive.enc");
        encrypt_paths_for_alice(&[content, sender_doc], &enc);

        let dest = dir.path().join("dest");
        let (_, expected) = alice_only();
        decrypt_paths_with_key(&enc, &dest, key_alice(), &expected).unwrap();
        assert_eq!(
            std::fs::read(dest.join("contenu.txt")).unwrap(),
            b"le vrai contenu"
        );
        assert_eq!(
            std::fs::read(dest.join("_expediteur.json")).unwrap(),
            br#"{"identity":"alice"}"#
        );
    }
}
