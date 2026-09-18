# Politique de sécurité

## Signaler une vulnérabilité

**Merci de ne pas ouvrir d'issue publique** pour toute faille touchant :
- l'orchestration multi-destinataires (scellement/descellement de la
  clé de contenu pour chaque destinataire),
- une possibilité de contournement de l'atomicité de l'extraction
  (archives multi-fichiers),
- la gestion mémoire des secrets pendant le chiffrement/déchiffrement.

merci de prendre contact pour inclure :
- une description du problème et son impact potentiel,
- les étapes de reproduction ou un PoC minimal,
- la version/commit concerné.

## Délai de réponse visé

A définir

## Versions supportées

| Version | Supportée |
|---|---|
| dernière version publiée | ✅ |
| versions antérieures | ❌ |

## Périmètre

Ce dépôt couvre `chiffre-rsa-enveloppe`. Les vulnérabilités touchant
les primitives RSA bas niveau relèvent de
[`chiffre-rsa-core`](https://github.com/sebnoy/chiffre-rsa-core) ; celles
touchant le cœur symétrique relèvent de
[`chiffre-aes-core`](https://github.com/sebnoy/chiffre-aes-core) ; celles
touchant la vérification/classification de clés relèvent de
[`chiffre-rsa-keystore`](https://github.com/sebnoy/chiffre-rsa-keystore).
