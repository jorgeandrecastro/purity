// Copyright (C) 2026 Jorge Andre Castro
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

#![deny(missing_docs)]
#![forbid(unsafe_code)]

//! # Purity
//!
//! `purity` est une bibliothèque de détection anti-bot et anti-spam légère,
//! conçue pour le projet Hodoe. Elle combine trois signaux complémentaires :
//!
//! - **Empreinte de contenu** : détecte les publications dupliquées ou quasi
//!   identiques (spam par copier-coller).
//! - **Limitation de fréquence (rate limiting)** : détecte un volume d'actions
//!   anormalement élevé pour un même auteur sur une courte période.
//! - **Qualité du contenu** : détecte les patterns typiques de spam (texte en
//!   majuscules, répétition excessive de caractères, surcharge de liens).
//!
//! ## Exemple d'utilisation
//!
//! ```rust
//! use purity::{PurityConfig, PurityGuard};
//!
//! let mut guard = PurityGuard::new(PurityConfig::default());
//! let now = 1_700_000_000;
//!
//! let verdict = guard.evaluate("author_1", "Un vrai message authentique.", now);
//! assert!(verdict.is_clean());
//!
//! // La même publication, republiée par le même auteur, est détectée.
//! let verdict2 = guard.evaluate("author_1", "Un vrai message authentique.", now + 1);
//! assert!(verdict2.is_duplicate);
//! ```
//!
//! ## Utilisation sans état (persistance externe)
//!
//! Si vous préférez stocker doublons et fréquence vous-même (par exemple en
//! base de données, pour survivre aux redémarrages du serveur), utilisez
//! [`content_fingerprint`] et [`evaluate_quality`] plutôt que [`PurityGuard`] :
//!
//! ```rust
//! use purity::{content_fingerprint, evaluate_quality, PurityConfig};
//!
//! let fp = content_fingerprint("Un message à stocker en base");
//! let quality = evaluate_quality("Un message à stocker en base", &PurityConfig::default());
//! assert!(quality.is_clean());
//! ```

use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::{Hash, Hasher};

/// Configuration des seuils de détection anti-bot de Purity.
///
/// Toutes les valeurs par défaut sont accessibles via [`PurityConfig::default`],
/// et peuvent être surchargées individuellement grâce aux méthodes `with_*`
/// (pattern builder), comme dans `ethosfeed::EthosConfig`.
#[derive(Debug, Clone, PartialEq)]
pub struct PurityConfig {
    /// Nombre maximal d'actions autorisées dans la fenêtre de temps `rate_window_secs`
    /// avant qu'un auteur soit considéré en excès de fréquence.
    pub rate_limit_max_actions: usize,
    /// Durée de la fenêtre glissante utilisée pour le rate limiting (en secondes).
    pub rate_window_secs: u64,
    /// Longueur minimale de contenu (en caractères) en dessous de laquelle
    /// une publication est considérée comme trop pauvre pour être fiable.
    pub min_content_length: usize,
    /// Proportion maximale de caractères en majuscules tolérée (0.0 à 1.0)
    /// avant de signaler un contenu comme suspect ("cri" typique du spam).
    pub max_uppercase_ratio: f64,
    /// Nombre maximal de liens (`http://` / `https://`) tolérés dans un
    /// contenu avant de le signaler comme spam de liens.
    pub max_links: usize,
    /// Longueur maximale d'une répétition consécutive du même caractère
    /// avant de signaler un contenu comme spam ("aaaaaaaaaa").
    pub max_char_repetition: usize,
}

impl Default for PurityConfig {
    /// Initialise la configuration avec des seuils standards, pensés pour
    /// un réseau social à contenu texte court à moyen.
    fn default() -> Self {
        Self {
            rate_limit_max_actions: 5,
            rate_window_secs: 60,
            min_content_length: 3,
            max_uppercase_ratio: 0.7,
            max_links: 3,
            max_char_repetition: 6,
        }
    }
}

impl PurityConfig {
    /// Retourne une copie de la configuration avec une nouvelle limite d'actions.
    pub fn with_rate_limit_max_actions(mut self, max: usize) -> Self {
        self.rate_limit_max_actions = max;
        self
    }

    /// Retourne une copie de la configuration avec une nouvelle fenêtre de temps.
    pub fn with_rate_window_secs(mut self, secs: u64) -> Self {
        self.rate_window_secs = secs;
        self
    }

    /// Retourne une copie de la configuration avec une nouvelle longueur minimale.
    pub fn with_min_content_length(mut self, len: usize) -> Self {
        self.min_content_length = len;
        self
    }

    /// Retourne une copie de la configuration avec un nouveau ratio de majuscules max.
    pub fn with_max_uppercase_ratio(mut self, ratio: f64) -> Self {
        self.max_uppercase_ratio = ratio;
        self
    }

    /// Retourne une copie de la configuration avec un nouveau nombre de liens max.
    pub fn with_max_links(mut self, max: usize) -> Self {
        self.max_links = max;
        self
    }

    /// Retourne une copie de la configuration avec une nouvelle limite de répétition.
    pub fn with_max_char_repetition(mut self, max: usize) -> Self {
        self.max_char_repetition = max;
        self
    }
}

/// Résultat de l'évaluation d'un contenu par [`PurityGuard::evaluate`].
///
/// Un verdict n'est jamais bloquant en lui-même : c'est à l'appelant de
/// décider quoi faire (rejeter, marquer pour modération, limiter la portée...)
/// en fonction des signaux remontés.
#[derive(Debug, Clone, PartialEq)]
pub struct PurityVerdict {
    /// `true` si ce contenu (ou un contenu quasi identique) a déjà été vu
    /// pour cet auteur.
    pub is_duplicate: bool,
    /// `true` si l'auteur a dépassé la limite d'actions autorisées sur la
    /// fenêtre de temps configurée.
    pub is_rate_limited: bool,
    /// `true` si le contenu est trop court pour être considéré comme
    /// significatif.
    pub is_too_short: bool,
    /// `true` si le contenu contient une proportion de majuscules excessive.
    pub is_shouting: bool,
    /// `true` si le contenu contient trop de liens.
    pub has_link_spam: bool,
    /// `true` si le contenu contient une répétition de caractère excessive.
    pub has_char_spam: bool,
}

impl PurityVerdict {
    /// Retourne `true` si aucun signal suspect n'a été détecté.
    pub fn is_clean(&self) -> bool {
        !self.is_duplicate
            && !self.is_rate_limited
            && !self.is_too_short
            && !self.is_shouting
            && !self.has_link_spam
            && !self.has_char_spam
    }

    /// Retourne la liste des raisons de suspicion, sous forme de chaînes
    /// lisibles, utile pour du logging ou une file de modération.
    pub fn reasons(&self) -> Vec<&'static str> {
        let mut reasons = Vec::new();
        if self.is_duplicate {
            reasons.push("contenu dupliqué");
        }
        if self.is_rate_limited {
            reasons.push("fréquence de publication excessive");
        }
        if self.is_too_short {
            reasons.push("contenu trop court");
        }
        if self.is_shouting {
            reasons.push("majuscules excessives");
        }
        if self.has_link_spam {
            reasons.push("trop de liens");
        }
        if self.has_char_spam {
            reasons.push("répétition de caractères excessive");
        }
        reasons
    }
}

/// Garde anti-bot avec état, à conserver en mémoire (ou derrière un verrou)
/// pour la durée de vie du serveur.
///
/// Contrairement à `ethosfeed::EthosConfig` qui est sans état, `PurityGuard`
/// maintient un historique par auteur (empreintes vues, horodatages d'actions)
/// nécessaire pour détecter les doublons et le rate limiting dans le temps.
///
/// **Limite connue** : cet historique vit uniquement en mémoire du processus.
/// Il est perdu à chaque redémarrage du serveur (déploiement, mise en veille
/// d'une plateforme comme Render en plan gratuit, etc.). Si vous avez besoin
/// que la détection de doublons et le rate limiting survivent aux
/// redémarrages, préférez [`content_fingerprint`] et [`evaluate_quality`]
/// combinés à votre propre persistance (ex: en base de données).
pub struct PurityGuard {
    config: PurityConfig,
    seen_fingerprints: HashMap<String, HashSet<u64>>,
    action_log: HashMap<String, VecDeque<u64>>,
}

impl PurityGuard {
    /// Crée un nouveau garde anti-bot avec la configuration fournie.
    pub fn new(config: PurityConfig) -> Self {
        Self {
            config,
            seen_fingerprints: HashMap::new(),
            action_log: HashMap::new(),
        }
    }

    /// Calcule une empreinte stable d'un contenu, insensible à la casse et
    /// aux espaces superflus en début/fin de texte.
    pub fn calculate_fingerprint(&self, content: &str) -> u64 {
        let normalized = content.trim().to_lowercase();
        let mut hasher = DefaultHasher::new();
        normalized.hash(&mut hasher);
        hasher.finish()
    }

    /// Évalue un contenu pour un auteur donné à l'instant `now` (timestamp Unix
    /// en secondes), et retourne un verdict complet combinant tous les signaux.
    ///
    /// Cette méthode a un effet de bord : elle enregistre l'action (empreinte +
    /// horodatage) dans l'historique interne, qu'elle soit jugée suspecte ou non.
    pub fn evaluate(&mut self, author_id: &str, content: &str, now: u64) -> PurityVerdict {
        let is_duplicate = self.check_and_record_duplicate(author_id, content);
        let is_rate_limited = self.check_and_record_rate_limit(author_id, now);
        let trimmed = content.trim();

        PurityVerdict {
            is_duplicate,
            is_rate_limited,
            is_too_short: trimmed.chars().count() < self.config.min_content_length,
            is_shouting: Self::uppercase_ratio(trimmed) > self.config.max_uppercase_ratio,
            has_link_spam: Self::count_links(trimmed) > self.config.max_links,
            has_char_spam: Self::max_repetition(trimmed) > self.config.max_char_repetition,
        }
    }

    /// Vérifie si un contenu est un doublon pour cet auteur, et enregistre
    /// son empreinte dans tous les cas (doublon ou non).
    fn check_and_record_duplicate(&mut self, author_id: &str, content: &str) -> bool {
        let fp = self.calculate_fingerprint(content);
        let entry = self.seen_fingerprints.entry(author_id.to_string()).or_default();

        if entry.contains(&fp) {
            true
        } else {
            entry.insert(fp);
            false
        }
    }

    /// Vérifie si l'auteur dépasse la limite d'actions sur la fenêtre glissante,
    /// et enregistre l'action actuelle dans tous les cas.
    fn check_and_record_rate_limit(&mut self, author_id: &str, now: u64) -> bool {
        let window_start = now.saturating_sub(self.config.rate_window_secs);
        let log = self.action_log.entry(author_id.to_string()).or_default();

        while let Some(&oldest) = log.front() {
            if oldest < window_start {
                log.pop_front();
            } else {
                break;
            }
        }

        log.push_back(now);
        log.len() > self.config.rate_limit_max_actions
    }

    /// Calcule la proportion de caractères alphabétiques en majuscule dans le texte.
    fn uppercase_ratio(text: &str) -> f64 {
        let letters: Vec<char> = text.chars().filter(|c| c.is_alphabetic()).collect();
        if letters.is_empty() {
            return 0.0;
        }
        let uppercase_count = letters.iter().filter(|c| c.is_uppercase()).count();
        uppercase_count as f64 / letters.len() as f64
    }

    /// Compte le nombre d'occurrences de `http://` ou `https://` dans le texte.
    fn count_links(text: &str) -> usize {
        text.matches("http://").count() + text.matches("https://").count()
    }

    /// Retourne la plus longue séquence de répétition consécutive d'un même
    /// caractère dans le texte (ex: "aaaaaaaaaa" -> 10).
    fn max_repetition(text: &str) -> usize {
        let mut max_run = 0;
        let mut current_run = 0;
        let mut last_char: Option<char> = None;

        for c in text.chars() {
            if Some(c) == last_char {
                current_run += 1;
            } else {
                current_run = 1;
                last_char = Some(c);
            }
            max_run = max_run.max(current_run);
        }

        max_run
    }

    /// Réinitialise complètement l'historique (empreintes et actions) pour
    /// un auteur donné. Utile après une revue manuelle de modération.
    pub fn reset_author(&mut self, author_id: &str) {
        self.seen_fingerprints.remove(author_id);
        self.action_log.remove(author_id);
    }

    /// Réinitialise complètement l'état du garde, tous auteurs confondus.
    pub fn reset_all(&mut self) {
        self.seen_fingerprints.clear();
        self.action_log.clear();
    }
}

/// Calcule l'empreinte d'un contenu de façon totalement indépendante de tout
/// état interne. Utile pour stocker l'empreinte en base de données et faire
/// de la détection de doublons persistante côté appelant.
pub fn content_fingerprint(content: &str) -> u64 {
    let normalized = content.trim().to_lowercase();
    let mut hasher = DefaultHasher::new();
    normalized.hash(&mut hasher);
    hasher.finish()
}

/// Résultat de l'évaluation de la qualité d'un contenu, sans aucune notion
/// d'historique (pas de doublon, pas de fréquence) — utile quand l'appelant
/// gère lui-même la persistance de ces deux signaux (ex: en base de données)
/// et ne veut de Purity que l'analyse du texte lui-même.
#[derive(Debug, Clone, PartialEq)]
pub struct QualityVerdict {
    /// `true` si le contenu est trop court pour être considéré comme significatif.
    pub is_too_short: bool,
    /// `true` si le contenu contient une proportion de majuscules excessive.
    pub is_shouting: bool,
    /// `true` si le contenu contient trop de liens.
    pub has_link_spam: bool,
    /// `true` si le contenu contient une répétition de caractère excessive.
    pub has_char_spam: bool,
}

impl QualityVerdict {
    /// Retourne `true` si aucun signal de qualité suspect n'a été détecté.
    pub fn is_clean(&self) -> bool {
        !self.is_too_short && !self.is_shouting && !self.has_link_spam && !self.has_char_spam
    }

    /// Retourne la liste des raisons de suspicion, sous forme lisible.
    pub fn reasons(&self) -> Vec<&'static str> {
        let mut reasons = Vec::new();
        if self.is_too_short {
            reasons.push("contenu trop court");
        }
        if self.is_shouting {
            reasons.push("majuscules excessives");
        }
        if self.has_link_spam {
            reasons.push("trop de liens");
        }
        if self.has_char_spam {
            reasons.push("répétition de caractères excessive");
        }
        reasons
    }
}

/// Analyse la qualité d'un contenu de façon totalement indépendante de tout
/// historique (pas de détection de doublon, pas de rate limiting).
///
/// À utiliser quand l'appelant gère lui-même la persistance des doublons et
/// de la fréquence de publication (par exemple en base de données), et ne
/// veut de Purity que l'analyse du texte.
pub fn evaluate_quality(content: &str, config: &PurityConfig) -> QualityVerdict {
    let trimmed = content.trim();

    QualityVerdict {
        is_too_short: trimmed.chars().count() < config.min_content_length,
        is_shouting: PurityGuard::uppercase_ratio(trimmed) > config.max_uppercase_ratio,
        has_link_spam: PurityGuard::count_links(trimmed) > config.max_links,
        has_char_spam: PurityGuard::max_repetition(trimmed) > config.max_char_repetition,
    }
}

// ============================================================================
// TESTS UNITAIRES
// ============================================================================
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_content_passes() {
        let mut guard = PurityGuard::new(PurityConfig::default());
        let verdict = guard.evaluate("author_1", "Un message authentique et réfléchi.", 1000);
        assert!(verdict.is_clean());
    }

    #[test]
    fn test_duplicate_detection() {
        let mut guard = PurityGuard::new(PurityConfig::default());
        let content = "Toujours le même message";

        let first = guard.evaluate("author_1", content, 1000);
        assert!(!first.is_duplicate);

        let second = guard.evaluate("author_1", content, 1001);
        assert!(second.is_duplicate);
    }

    #[test]
    fn test_duplicate_is_case_and_whitespace_insensitive() {
        let mut guard = PurityGuard::new(PurityConfig::default());

        let first = guard.evaluate("author_1", "  Bonjour Le Monde  ", 1000);
        assert!(!first.is_duplicate);

        let second = guard.evaluate("author_1", "bonjour le monde", 1001);
        assert!(second.is_duplicate);
    }

    #[test]
    fn test_duplicate_is_per_author() {
        let mut guard = PurityGuard::new(PurityConfig::default());
        let content = "Message partagé par deux auteurs différents";

        let first = guard.evaluate("author_1", content, 1000);
        let second = guard.evaluate("author_2", content, 1001);

        assert!(!first.is_duplicate);
        assert!(!second.is_duplicate);
    }

    #[test]
    fn test_rate_limiting_triggers_after_threshold() {
        let config = PurityConfig::default().with_rate_limit_max_actions(3);
        let mut guard = PurityGuard::new(config);

        for i in 0..3 {
            let verdict = guard.evaluate("author_1", &format!("message {i}"), 1000 + i);
            assert!(!verdict.is_rate_limited, "action {i} ne devrait pas être limitée");
        }

        let verdict = guard.evaluate("author_1", "message 4", 1004);
        assert!(verdict.is_rate_limited);
    }

    #[test]
    fn test_rate_limit_window_expires() {
        let config = PurityConfig::default()
            .with_rate_limit_max_actions(2)
            .with_rate_window_secs(10);
        let mut guard = PurityGuard::new(config);

        guard.evaluate("author_1", "a", 1000);
        guard.evaluate("author_1", "b", 1001);
        let limited = guard.evaluate("author_1", "c", 1002);
        assert!(limited.is_rate_limited);

        let after_window = guard.evaluate("author_1", "d", 1020);
        assert!(!after_window.is_rate_limited);
    }

    #[test]
    fn test_too_short_content() {
        let mut guard = PurityGuard::new(PurityConfig::default());
        let verdict = guard.evaluate("author_1", "ok", 1000);
        assert!(verdict.is_too_short);
    }

    #[test]
    fn test_shouting_detection() {
        let mut guard = PurityGuard::new(PurityConfig::default());
        let verdict = guard.evaluate("author_1", "ACHETEZ MAINTENANT VITE VITE", 1000);
        assert!(verdict.is_shouting);
    }

    #[test]
    fn test_normal_capitalization_is_not_shouting() {
        let mut guard = PurityGuard::new(PurityConfig::default());
        let verdict = guard.evaluate("author_1", "Ceci est une phrase normale.", 1000);
        assert!(!verdict.is_shouting);
    }

    #[test]
    fn test_link_spam_detection() {
        let mut guard = PurityGuard::new(PurityConfig::default());
        let content = "Regarde http://a.com http://b.com http://c.com http://d.com";
        let verdict = guard.evaluate("author_1", content, 1000);
        assert!(verdict.has_link_spam);
    }

    #[test]
    fn test_char_repetition_spam() {
        let mut guard = PurityGuard::new(PurityConfig::default());
        let verdict = guard.evaluate("author_1", "wahouuuuuuuuuu incroyable", 1000);
        assert!(verdict.has_char_spam);
    }

    #[test]
    fn test_reset_author_clears_history() {
        let mut guard = PurityGuard::new(PurityConfig::default());
        let content = "message unique";

        guard.evaluate("author_1", content, 1000);
        guard.reset_author("author_1");

        let verdict = guard.evaluate("author_1", content, 1001);
        assert!(!verdict.is_duplicate);
    }

    #[test]
    fn test_reasons_lists_all_triggered_signals() {
        let config = PurityConfig::default().with_min_content_length(50);
        let mut guard = PurityGuard::new(config);
        let verdict = guard.evaluate("author_1", "COURT", 1000);

        assert!(verdict.is_too_short);
        assert!(verdict.is_shouting);
        assert!(verdict.reasons().contains(&"contenu trop court"));
        assert!(verdict.reasons().contains(&"majuscules excessives"));
    }

    #[test]
    fn test_builder_pattern_overrides_defaults() {
        let config = PurityConfig::default()
            .with_max_links(1)
            .with_max_uppercase_ratio(0.9);

        assert_eq!(config.max_links, 1);
        assert_eq!(config.max_uppercase_ratio, 0.9);
        assert_eq!(config.rate_limit_max_actions, PurityConfig::default().rate_limit_max_actions);
    }

    #[test]
    fn test_content_fingerprint_matches_case_and_whitespace_insensitive() {
        let fp1 = content_fingerprint("  Bonjour Le Monde  ");
        let fp2 = content_fingerprint("bonjour le monde");
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_evaluate_quality_is_stateless() {
        let config = PurityConfig::default();

        let first = evaluate_quality("Un message authentique.", &config);
        let second = evaluate_quality("Un message authentique.", &config);
        assert_eq!(first, second);
        assert!(first.is_clean());
    }

    #[test]
    fn test_evaluate_quality_detects_shouting() {
        let config = PurityConfig::default();
        let verdict = evaluate_quality("ACHETEZ MAINTENANT VITE VITE", &config);
        assert!(verdict.is_shouting);
    }
}