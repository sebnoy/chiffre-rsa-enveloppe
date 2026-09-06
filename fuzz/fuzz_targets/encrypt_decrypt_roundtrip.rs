//! Fuzz de propriété : `encrypt_file_for_recipients` puis
//! `decrypt_file_with_key` sur un contenu de fichier **arbitraire**
//! (`data`), avec une clé RSA fixe comme unique destinataire — le
//! contenu déchiffré doit toujours être identique au contenu d'origine.
//!
//! Contrairement à `decrypt_file_with_key` (l'autre cible de ce
//! harnais), il n'y a ici aucune entrée non authentifiée au sens
//! sécurité : c'est un test de propriété (aller-retour = identité) plutôt
//! qu'un test de robustesse face à un attaquant. Intérêt : les tests
//! unitaires n'utilisent que quelques chaînes ASCII fixes comme contenu ;
//! le fuzzing explore des contenus arbitraires (octets nuls, motifs
//! répétitifs, tailles inhabituelles y compris 0 octet) qu'on
//! n'énumérerait pas à la main, et qui pourraient révéler un bug
//! d'orchestration (troncature, décalage d'offset) qui ne se verrait pas
//! sur un texte ASCII court.
//!
//! Un panic ici (y compris l'assertion d'égalité) est un vrai bug de ce
//! crate à corriger — pas un comportement attendu comme pour
//! `decrypt_file_with_key`.

#![no_main]

use chiffre_rsa_core::RsaKeyPair;
use chiffre_rsa_enveloppe::{decrypt_file_with_key, encrypt_file_for_recipients, RecipientRef};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

const FIXED_PRIVATE_KEY_PEM: &str = include_str!("../fixed_key.pem");

fn fixed_key() -> &'static RsaKeyPair {
    static KEY: OnceLock<RsaKeyPair> = OnceLock::new();
    KEY.get_or_init(|| {
        RsaKeyPair::from_pkcs8_pem(FIXED_PRIVATE_KEY_PEM, None)
            .expect("clé de fuzzing fixe invalide")
    })
}

fuzz_target!(|data: &[u8]| {
    let Ok(tmp) = tempfile::tempdir() else {
        return;
    };
    let input_path = tmp.path().join("plain.dat");
    let enc_path = tmp.path().join("out.enc");
    let decrypted_path = tmp.path().join("decrypted.dat");

    if std::fs::write(&input_path, data).is_err() {
        return;
    }

    let key = fixed_key();
    let public_key = key.public_key();

    encrypt_file_for_recipients(
        &input_path,
        &enc_path,
        &[RecipientRef {
            public_key: &public_key,
        }],
    )
    .expect("le chiffrement pour un unique destinataire fixe ne doit jamais échouer");

    decrypt_file_with_key(&enc_path, &decrypted_path, key)
        .expect("le déchiffrement par le destinataire légitime ne doit jamais échouer");

    let decrypted = std::fs::read(&decrypted_path).expect("lecture du fichier déchiffré");
    assert_eq!(
        decrypted, data,
        "le contenu déchiffré diffère du contenu d'origine"
    );
});
