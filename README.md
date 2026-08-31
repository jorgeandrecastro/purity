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
purity = "0.1"
```

Aucune dépendance externe : la bibliothèque repose uniquement sur `std`.

## Démarrage rapide

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

`PurityGuard` maintient un état interne (empreintes vues, horodatages par auteur) — instanciez-le une seule fois et conservez-le pour la durée de vie de votre serveur (par exemple dans votre `AppState` Axum).

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

## License

GPL-2.0-or-later
Copyright (C) 2026 Jorge Andre Castro