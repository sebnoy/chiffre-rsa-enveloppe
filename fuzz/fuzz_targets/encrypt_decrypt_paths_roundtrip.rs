//! Fuzz de propriété : `encrypt_paths_for_recipients` puis
//! `decrypt_paths_with_key` sur DEUX fichiers de contenu **arbitraire**
//! (dérivés d'un seul buffer fuzzé, coupé à une position elle-même
//! dérivée du buffer — même technique que `verify.rs` côté
//! `chiffre-rsa-core`), avec une clé RSA fixe comme unique destinataire.
//! Les deux fichiers reconstruits doivent être identiques aux deux
//! fichiers d'origine.
//!
//! Deux fichiers plutôt qu'un seul (contrairement à
//! `encrypt_decrypt_roundtrip.rs`, qui teste la voie mono-fichier) :
//! c'est justement le passage par une VRAIE archive multi-entrées
//! (`build_archive`/`extract_archive`) que cette cible-ci doit exercer,
//! pas seulement le chiffrement/déchiffrement AEAD d'un unique flux.
//!
//! Comme `encrypt_decrypt_roundtrip.rs`, un panic ici (y compris
//! l'assertion d'égalité) est un vrai bug de ce crate à corriger — pas
//! un comportement attendu face à une entrée hostile : il n'y a aucune
//! entrée non authentifiée dans ce scénario, seulement une propriété
//! d'aller-retour qui doit toujours tenir.

#![no_main]

use chiffre_rsa_core::RsaKeyPair;
use chiffre_rsa_enveloppe::{decrypt_paths_with_key, encrypt_paths_for_recipients, RecipientRef};
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
    if data.is_empty() {
        return;
    }
    let cut = (data[0] as usize) % data.len().max(1);
    let (content_a, content_b) = data[1..].split_at(cut.min(data.len().saturating_sub(1)));

    let Ok(tmp) = tempfile::tempdir() else {
        return;
    };
    let path_a = tmp.path().join("fichier_a.dat");
    let path_b = tmp.path().join("fichier_b.dat");
    let enc_path = tmp.path().join("archive.enc");
    let dest_dir = tmp.path().join("dest");

    if std::fs::write(&path_a, content_a).is_err() || std::fs::write(&path_b, content_b).is_err()
    {
        return;
    }

    let key = fixed_key();
    let public_key = key.public_key();

    encrypt_paths_for_recipients(
        &[path_a, path_b],
        &enc_path,
        &[RecipientRef {
            public_key: &public_key,
        }],
    )
    .expect("le chiffrement pour un unique destinataire fixe ne doit jamais échouer");

    decrypt_paths_with_key(&enc_path, &dest_dir, key)
        .expect("le déchiffrement par le destinataire légitime ne doit jamais échouer");

    let extracted_a =
        std::fs::read(dest_dir.join("fichier_a.dat")).expect("lecture du fichier A extrait");
    let extracted_b =
        std::fs::read(dest_dir.join("fichier_b.dat")).expect("lecture du fichier B extrait");

    assert_eq!(extracted_a, content_a, "contenu du fichier A altéré par l'aller-retour");
    assert_eq!(extracted_b, content_b, "contenu du fichier B altéré par l'aller-retour");
});
