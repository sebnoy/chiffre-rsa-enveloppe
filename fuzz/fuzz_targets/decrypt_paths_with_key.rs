//! Fuzz `decrypt_paths_with_key` sur un contenu de fichier `.enc`
//! arbitraire, avec une clé RSA privée FIXE — même raison que
//! `decrypt_file_with_key.rs` : générer une paire à chaque itération
//! serait prohibitif et n'apporterait rien à la propriété recherchée.
//!
//! Contrairement à `decrypt_file_with_key`, cette cible exerce en plus
//! le désarchivage (`chiffre_aes_core::archive::extract_archive`) une
//! fois le déchiffrement AEAD passé — donc, par construction, la très
//! grande majorité des entrées aléatoires n'iront pas plus loin que le
//! rejet du header ou l'échec d'authentification AEAD (la probabilité
//! qu'un buffer aléatoire passe l'authentification GCM est
//! négligeable). C'est attendu : cette cible complète
//! `decrypt_file_with_key` sur la surface propre à ce crate (recherche
//! de destinataire), pas sur le désarchivage lui-même — voir
//! `encrypt_decrypt_paths_roundtrip.rs` pour la cible qui, elle, atteint
//! réellement `extract_archive` avec un contenu authentifié.
//!
//! Chaque itération utilise un nouveau dossier de destination (jamais
//! réutilisé), pour toujours exercer la branche "bascule atomique via
//! rename" plutôt que la branche "destination déjà existante" — voir
//! `encrypt_decrypt_paths_roundtrip.rs` et les tests unitaires de
//! `src/lib.rs` pour la couverture de l'autre branche.
//!
//! Propriété recherchée : jamais de panic, quelle que soit l'entrée.

#![no_main]

use chiffre_rsa_core::RsaKeyPair;
use libfuzzer_sys::fuzz_target;
use std::io::Write;
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
    let enc_path = tmp.path().join("fuzz_input.enc");
    let dest_dir = tmp.path().join("dest"); // jamais créé à l'avance

    let Ok(mut f) = std::fs::File::create(&enc_path) else {
        return;
    };
    if f.write_all(data).is_err() {
        return;
    }
    drop(f);

    let _ = chiffre_rsa_enveloppe::decrypt_paths_with_key(&enc_path, &dest_dir, fixed_key());
});
