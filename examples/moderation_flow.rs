// Copyright (C) 2026 Jorge Andre Castro
// License: GPL-2.0-or-later
//
// Exemple : simuler un flux de publications, certaines légitimes, d'autres
// suspectes, et observer comment PurityGuard les distingue.
//
// Lancer avec : cargo run --example moderation_flow

use purity::{PurityConfig, PurityGuard};

fn main() {
    let config = PurityConfig::default().with_rate_limit_max_actions(3);
    let mut guard = PurityGuard::new(config);

    let events: Vec<(&str, &str, u64)> = vec![
        ("alice", "Voici mon projet du jour, un site en Rust.", 1000),
        ("bob", "ACHETEZ MAINTENANT PROMO INCROYABLE", 1001),
        ("alice", "Voici mon projet du jour, un site en Rust.", 1002), // doublon
        ("bob", "http://spam1.com http://spam2.com http://spam3.com http://spam4.com", 1003),
        ("carol", "ok", 1004),
        ("dave", "post 1", 1005),
        ("dave", "post 2", 1006),
        ("dave", "post 3", 1007),
        ("dave", "post 4", 1008), // dépasse la limite de fréquence
    ];

    for (author, content, timestamp) in events {
        let verdict = guard.evaluate(author, content, timestamp);
        if verdict.is_clean() {
            println!("✅ [{author}] accepté : \"{content}\"");
        } else {
            println!(
                "🚫 [{author}] signalé ({}) : \"{content}\"",
                verdict.reasons().join(", ")
            );
        }
    }
}