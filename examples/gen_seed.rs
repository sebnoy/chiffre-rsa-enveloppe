//! Utilitaire de développement : chiffre un fichier pour la clé RSA fixe
//! utilisée par les harnais de fuzzing (`fuzz/fixed_key.pem`), pour
//! obtenir un vrai `.enc` v2 valide à déposer comme seed dans
//! `fuzz/corpus/decrypt_file_with_key/`.
//!
//! Usage : `cargo run --example gen_seed -- <entrée> <sortie.enc>`

use chiffre_rsa_core::{RsaKeyPair, RsaPublicKey};
use chiffre_rsa_enveloppe::{encrypt_file_for_recipients, RecipientRef};
use std::path::PathBuf;

const FIXED_PRIVATE_KEY_PEM: &str = include_str!("../fuzz/fixed_key.pem");

fn main() {
    let mut args = std::env::args().skip(1);
    let input = PathBuf::from(args.next().expect("usage: gen_seed <entrée> <sortie.enc>"));
    let output = PathBuf::from(args.next().expect("usage: gen_seed <entrée> <sortie.enc>"));

    let key_pair =
        RsaKeyPair::from_pkcs8_pem(FIXED_PRIVATE_KEY_PEM, None).expect("clé fixe invalide");
    let public_key: RsaPublicKey = key_pair.public_key();

    encrypt_file_for_recipients(
        &input,
        &output,
        &[RecipientRef {
            public_key: &public_key,
        }],
    )
    .expect("chiffrement");

    println!("Écrit : {}", output.display());
}
