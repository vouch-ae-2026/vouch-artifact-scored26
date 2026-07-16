//! Contract-only evaluator metering.
//!
//! The general interpreter's recursion counter measures host-stack growth and
//! deliberately ignores tail calls.  The SCORED contract instead counts every
//! entered Core form and every primitive invocation, and defines depth as the
//! number of active logical evaluator frames.  This observer is therefore a
//! separate, opt-in accounting lane.

use std::cell::RefCell;
use std::rc::Rc;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BudgetFaultKind {
    Step,
    Depth,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BudgetFault {
    pub kind: BudgetFaultKind,
    pub steps_used: usize,
    pub depth: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MeterEventKind {
    Form,
    Primitive,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MeterEvent {
    pub kind: MeterEventKind,
    pub step: usize,
    pub depth: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MeterSnapshot {
    pub steps_used: usize,
    pub active_depth: usize,
    pub maximum_depth: usize,
    pub trace: Vec<MeterEvent>,
}

#[derive(Debug)]
struct MeterState {
    step_limit: usize,
    depth_limit: usize,
    steps_used: usize,
    active_depth: usize,
    maximum_depth: usize,
    trace: Vec<MeterEvent>,
}

/// A guard for one logical Core-form frame.
///
/// It owns shared state rather than borrowing the observer so evaluators can
/// retain guards across a trampoline iteration.  That is the load-bearing TCO
/// property: optimization of the host stack cannot collapse contract frames.
#[derive(Debug)]
pub struct FrameGuard {
    state: Rc<RefCell<MeterState>>,
    active: bool,
}

impl Drop for FrameGuard {
    fn drop(&mut self) {
        if self.active {
            let mut state = self.state.borrow_mut();
            debug_assert!(state.active_depth > 0);
            state.active_depth -= 1;
            self.active = false;
        }
    }
}

pub trait EvalObserver {
    fn enter_form(&mut self) -> Result<FrameGuard, BudgetFault>;
    fn primitive_call(&mut self) -> Result<(), BudgetFault>;
}

#[derive(Clone, Debug)]
pub struct BudgetObserver {
    state: Rc<RefCell<MeterState>>,
}

impl BudgetObserver {
    pub fn new(step_limit: usize, depth_limit: usize) -> Self {
        Self {
            state: Rc::new(RefCell::new(MeterState {
                step_limit,
                depth_limit,
                steps_used: 0,
                active_depth: 0,
                maximum_depth: 0,
                trace: Vec::new(),
            })),
        }
    }

    pub fn snapshot(&self) -> MeterSnapshot {
        let state = self.state.borrow();
        MeterSnapshot {
            steps_used: state.steps_used,
            active_depth: state.active_depth,
            maximum_depth: state.maximum_depth,
            trace: state.trace.clone(),
        }
    }

    fn charge_step(state: &mut MeterState) -> Result<usize, BudgetFault> {
        if state.steps_used >= state.step_limit {
            return Err(BudgetFault {
                kind: BudgetFaultKind::Step,
                steps_used: state.steps_used,
                depth: state.active_depth,
            });
        }
        state.steps_used += 1;
        Ok(state.steps_used)
    }
}

impl EvalObserver for BudgetObserver {
    fn enter_form(&mut self) -> Result<FrameGuard, BudgetFault> {
        let mut state = self.state.borrow_mut();
        let step = Self::charge_step(&mut state)?;
        if state.active_depth >= state.depth_limit {
            return Err(BudgetFault {
                kind: BudgetFaultKind::Depth,
                steps_used: state.steps_used,
                depth: state.active_depth,
            });
        }
        state.active_depth += 1;
        state.maximum_depth = state.maximum_depth.max(state.active_depth);
        let depth = state.active_depth;
        state.trace.push(MeterEvent {
            kind: MeterEventKind::Form,
            step,
            depth,
        });
        drop(state);
        Ok(FrameGuard {
            state: Rc::clone(&self.state),
            active: true,
        })
    }

    fn primitive_call(&mut self) -> Result<(), BudgetFault> {
        let mut state = self.state.borrow_mut();
        let step = Self::charge_step(&mut state)?;
        let depth = state.active_depth;
        state.trace.push(MeterEvent {
            kind: MeterEventKind::Primitive,
            step,
            depth,
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn succeeds_exactly_at_step_limit_and_faults_at_limit_plus_one() {
        let mut observer = BudgetObserver::new(2, 2);
        let _frame = observer.enter_form().unwrap();
        observer.primitive_call().unwrap();
        assert_eq!(observer.snapshot().steps_used, 2);
        assert_eq!(
            observer.primitive_call().unwrap_err(),
            BudgetFault {
                kind: BudgetFaultKind::Step,
                steps_used: 2,
                depth: 1,
            }
        );
    }

    #[test]
    fn failed_depth_entry_is_still_a_charged_form_entry() {
        let mut observer = BudgetObserver::new(3, 1);
        let _outer = observer.enter_form().unwrap();
        assert_eq!(
            observer.enter_form().unwrap_err().kind,
            BudgetFaultKind::Depth
        );
        let snapshot = observer.snapshot();
        assert_eq!(snapshot.steps_used, 2);
        assert_eq!(snapshot.active_depth, 1);
        assert_eq!(snapshot.maximum_depth, 1);
    }
}
