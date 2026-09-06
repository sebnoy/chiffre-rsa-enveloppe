//! Fuzz `decrypt_file_with_key` sur un contenu de fichier `.enc` v2
//! arbitraire, avec une clé RSA privée FIXE.
//!
//! C'est le pendant, au niveau orchestration, de la cible
//! `decrypt_file_with_raw_key` de `chiffre_aes_core` — mais ici la
//! surface visée est spécifique à `chiffre-rsa-enveloppe` : la
//! combinaison `inspect_key_requirement` → recherche de l'entrée
//! correspondant à `key.public_key().fingerprint()` → `unwrap_key`. Ce
//! chemin n'est exercé par AUCUNE des cibles de fuzzing de
//! `chiffre_aes_core` (qui ne connaît rien de RSA) ni de
//! `chiffre-rsa-core` (qui ne fait jamais la correspondance
//! `recipient_id` ↔ empreinte, uniquement `unwrap_key` sur un
//! `wrapped_key` déjà choisi par l'appelant).
//!
//! Clé fixe pour la même raison que côté `chiffre-rsa-core` : générer une
//! paire RSA-4096 à chaque itération serait prohibitif et n'apporterait
//! rien — la propriété recherchée porte sur la robustesse du parsing/de
//! la correspondance face à un fichier arbitraire, pas sur la génération
//! de clé.
//!
//! Propriété recherchée : jamais de panic, quelle que soit l'entrée —
//! `decrypt_file_with_key` doit toujours retourner un `Result`, jamais
//! paniquer, jamais consommer des ressources disproportionnées (ce
//! dernier point relève surtout de `chiffre_aes_core`, déjà fuzzé pour
//! ça, mais la boucle de recherche de destinataire ajoutée ici — bornée
//! par `MAX_RECIPIENTS = 64` côté format — est aussi couverte).

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
    let out_path = tmp.path().join("fuzz_output.dat");

    let Ok(mut f) = std::fs::File::create(&enc_path) else {
        return;
    };
    if f.write_all(data).is_err() {
        return;
    }
    drop(f);

    let _ = chiffre_rsa_enveloppe::decrypt_file_with_key(&enc_path, &out_path, fixed_key());
});
