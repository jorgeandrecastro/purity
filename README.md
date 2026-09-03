# purity

[![Crates.io](https://img.shields.io/crates/v/purity.svg)](https://crates.io/crates/purity)
[![Downloads](https://img.shields.io/crates/d/purity.svg)](https://crates.io/crates/purity)
[![docs.rs](https://docs.rs/purity/badge.svg)](https://docs.rs/purity)
[![License](https://img.shields.io/crates/l/purity.svg)](LICENSE)

Bibliothèque de détection anti-bot et anti-spam légère, conçue pour le projet **Hodoe**. Trois signaux complémentaires, combinés en un seul verdict par publication.

## Les trois signaux

| Signal | Détecte | Configurable via |
|---|---|---|
| Empreinte de contenu | Publications dupliquées ou quasi identiques par un même auteur | — (toujours actif) |
| Fréquence de publication | Volume d'actions anormalement élevé sur une courte période | `rate_limit_max_actions`, `rate_window_secs` |
| Qualité du contenu | Majuscules excessives, liens en masse, répétition de caractères, texte trop court | `max_uppercase_ratio`, `max_links`, `max_char_repetition`, `min_content_length` |

## Installation

```toml
[dependencies]
purity = "0.2"
```

Aucune dépendance externe : la bibliothèque repose uniquement sur `std`.

## Deux façons d'utiliser Purity

### Avec état  `PurityGuard`

Le plus simple : `PurityGuard` garde l'historique des publications en mémoire (empreintes vues, horodatages par auteur) et détecte doublons et excès de fréquence automatiquement.

```rust
use purity::{PurityConfig, PurityGuard};

let mut guard = PurityGuard::new(PurityConfig::default());
let now = 1_700_000_000;

let verdict = guard.evaluate("author_1", "Un vrai message authentique.", now);

if verdict.is_clean() {
    // publier normalement
} else {
    println!("Signalé : {}", verdict.reasons().join(", "));
}
```

Instanciez `PurityGuard` une seule fois et conservez-le pour la durée de vie de votre serveur (par exemple dans votre `AppState` Axum).

**Limite à connaître** : cet historique vit uniquement en mémoire du processus. Il est perdu à chaque redémarrage du serveur (déploiement, mise en veille d'une plateforme comme Render en plan gratuit, etc.). Si vous avez besoin que la détection de doublons et le rate limiting survivent aux redémarrages, utilisez plutôt les fonctions sans état ci-dessous, combinées à votre propre persistance.

### Sans état `content_fingerprint` et `evaluate_quality`

Nouveau en 0.2.0. Si vous préférez stocker doublons et fréquence vous-même (par exemple dans votre base de données, aux côtés de vos publications), utilisez ces deux fonctions indépendantes de tout état interne :

```rust
use purity::{content_fingerprint, evaluate_quality, PurityConfig};

let content = "Un message à publier";
let config = PurityConfig::default();

// Empreinte à stocker en base (ex: colonne `content_fingerprint` sur votre table de posts)
let fingerprint = content_fingerprint(content);

// Analyse de qualité, toujours sans état
let quality = evaluate_quality(content, &config);

if quality.is_clean() {
    // à combiner avec vos propres requêtes en base pour vérifier
    // doublons et fréquence de publication
}
```

C'est l'approche recommandée pour tout service déployé sur une plateforme qui peut redémarrer le processus (Render, Fly.io, Heroku...) : la détection reste fiable même après un redéploiement ou une mise en veille, puisque l'état vit dans votre base de données plutôt qu'en RAM.

## Personnaliser les seuils

```rust
use purity::PurityConfig;

let config = PurityConfig::default()
    .with_rate_limit_max_actions(10)
    .with_rate_window_secs(120)
    .with_max_links(1);
```

## Exemple complet

```bash
cargo run --example moderation_flow
```

## Historique des versions

- **0.2.0** : Ajout de `content_fingerprint` et `evaluate_quality`, deux fonctions sans état pour permettre une persistance externe (base de données) de la détection de doublons et du rate limiting.
- **0.1.0** : Version initiale : `PurityGuard` avec détection de doublons, rate limiting et qualité de contenu, tout en mémoire.

## License

GPL-2.0-or-later
Copyright (C) 2026 Jorge Andre Castro