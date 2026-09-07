//! Utilitaire de développement, pendant de `gen_seed.rs` pour la voie
//! archive multi-fichiers : chiffre plusieurs fichiers pour la clé RSA
//! fixe utilisée par les harnais de fuzzing (`fuzz/fixed_key.pem`), pour
//! obtenir un vrai `.enc` v2 (contenant une vraie archive interne) à
//! déposer comme seed dans `fuzz/corpus/decrypt_paths_with_key/`.
//!
//! Usage : `cargo run --example gen_paths_seed -- <sortie.enc> <entrée1> [<entrée2> ...]`

use chiffre_rsa_core::{RsaKeyPair, RsaPublicKey};
use chiffre_rsa_enveloppe::{encrypt_paths_for_recipients, RecipientRef};
use std::path::PathBuf;

const FIXED_PRIVATE_KEY_PEM: &str = include_str!("../fuzz/fixed_key.pem");

fn main() {
    let mut args = std::env::args().skip(1);
    let output = PathBuf::from(
        args.next()
            .expect("usage: gen_paths_seed <sortie.enc> <entrée1> [<entrée2> ...]"),
    );
    let inputs: Vec<PathBuf> = args.map(PathBuf::from).collect();
    if inputs.is_empty() {
        panic!("usage: gen_paths_seed <sortie.enc> <entrée1> [<entrée2> ...]");
    }

    let key_pair =
        RsaKeyPair::from_pkcs8_pem(FIXED_PRIVATE_KEY_PEM, None).expect("clé fixe invalide");
    let public_key: RsaPublicKey = key_pair.public_key();

    let warnings = encrypt_paths_for_recipients(
        &inputs,
        &output,
        &[RecipientRef {
            public_key: &public_key,
        }],
    )
    .expect("chiffrement");

    if !warnings.is_empty() {
        eprintln!("avertissements : {warnings:?}");
    }
    println!("Écrit : {}", output.display());
}
