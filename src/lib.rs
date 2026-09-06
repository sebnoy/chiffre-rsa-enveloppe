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

use std::path::Path;

use chiffre_aes_core::{HeaderKeyRequirement, RawKey, Recipient};
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
}
