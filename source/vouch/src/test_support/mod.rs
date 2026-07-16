//! Contract-only test support.

#[cfg(test)]
mod tests {
    #[test]
    fn mutation_cfg_matches_embedded_metadata() {
        let active = [
            (cfg!(scored_mutant = "M01"), "M01"),
            (cfg!(scored_mutant = "M02"), "M02"),
            (cfg!(scored_mutant = "M03"), "M03"),
            (cfg!(scored_mutant = "M04"), "M04"),
            (cfg!(scored_mutant = "M05"), "M05"),
            (cfg!(scored_mutant = "M06"), "M06"),
            (cfg!(scored_mutant = "M07"), "M07"),
            (cfg!(scored_mutant = "M08"), "M08"),
            (cfg!(scored_mutant = "M09"), "M09"),
            (cfg!(scored_mutant = "M10"), "M10"),
            (cfg!(scored_mutant = "M11"), "M11"),
            (cfg!(scored_mutant = "M12"), "M12"),
        ]
        .into_iter()
        .filter_map(|(active, name)| active.then_some(name))
        .collect::<Vec<_>>();
        let embedded = option_env!("CSK_SCORED_MUTANT").filter(|value| !value.is_empty());
        assert!(active.len() <= 1);
        assert_eq!(active.first().copied(), embedded);
    }
}
