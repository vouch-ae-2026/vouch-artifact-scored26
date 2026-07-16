//! Compile-time SCORED mutation-selection integrity guard.

#[cfg(scored_mutant_injected)]
compile_error!("SCORED mutant cfg must come only from the validated build-script selection");

#[allow(dead_code)]
const ACTIVE_SCORED_MUTANTS: usize = cfg!(scored_mutant = "M01") as usize
    + cfg!(scored_mutant = "M02") as usize
    + cfg!(scored_mutant = "M03") as usize
    + cfg!(scored_mutant = "M04") as usize
    + cfg!(scored_mutant = "M05") as usize
    + cfg!(scored_mutant = "M06") as usize
    + cfg!(scored_mutant = "M07") as usize
    + cfg!(scored_mutant = "M08") as usize
    + cfg!(scored_mutant = "M09") as usize
    + cfg!(scored_mutant = "M10") as usize
    + cfg!(scored_mutant = "M11") as usize
    + cfg!(scored_mutant = "M12") as usize;

#[cfg(scored_mutant_expected = "none")]
const _: () = assert!(ACTIVE_SCORED_MUTANTS == 0);

#[cfg(scored_mutant_expected = "M01")]
const _: () = assert!(ACTIVE_SCORED_MUTANTS == 1 && cfg!(scored_mutant = "M01"));

#[cfg(scored_mutant_expected = "M02")]
const _: () = assert!(ACTIVE_SCORED_MUTANTS == 1 && cfg!(scored_mutant = "M02"));

#[cfg(scored_mutant_expected = "M03")]
const _: () = assert!(ACTIVE_SCORED_MUTANTS == 1 && cfg!(scored_mutant = "M03"));

#[cfg(scored_mutant_expected = "M04")]
const _: () = assert!(ACTIVE_SCORED_MUTANTS == 1 && cfg!(scored_mutant = "M04"));

#[cfg(scored_mutant_expected = "M05")]
const _: () = assert!(ACTIVE_SCORED_MUTANTS == 1 && cfg!(scored_mutant = "M05"));

#[cfg(scored_mutant_expected = "M06")]
const _: () = assert!(ACTIVE_SCORED_MUTANTS == 1 && cfg!(scored_mutant = "M06"));

#[cfg(scored_mutant_expected = "M07")]
const _: () = assert!(ACTIVE_SCORED_MUTANTS == 1 && cfg!(scored_mutant = "M07"));

#[cfg(scored_mutant_expected = "M08")]
const _: () = assert!(ACTIVE_SCORED_MUTANTS == 1 && cfg!(scored_mutant = "M08"));

#[cfg(scored_mutant_expected = "M09")]
const _: () = assert!(ACTIVE_SCORED_MUTANTS == 1 && cfg!(scored_mutant = "M09"));

#[cfg(scored_mutant_expected = "M10")]
const _: () = assert!(ACTIVE_SCORED_MUTANTS == 1 && cfg!(scored_mutant = "M10"));

#[cfg(scored_mutant_expected = "M11")]
const _: () = assert!(ACTIVE_SCORED_MUTANTS == 1 && cfg!(scored_mutant = "M11"));

#[cfg(scored_mutant_expected = "M12")]
const _: () = assert!(ACTIVE_SCORED_MUTANTS == 1 && cfg!(scored_mutant = "M12"));

#[allow(dead_code)]
pub(crate) const SELECTED_MUTANT: &str = env!("CSK_SCORED_MUTANT");
