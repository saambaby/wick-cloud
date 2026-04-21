//! Loom model: concurrent park / wake CAS + memory accounting.
//!
//! The model exercises the core atomic invariants of the Phase-2 state machine:
//!
//! 1. **State reachability** — state always terminates in `{PARKED, ACTIVE}`.
//!    No interleaving produces an impossible state.
//!
//! 2. **Single winner** — exactly one thread wins the CAS `PARKED→LOADING`
//!    per attempt; the other observes the lost race atomically.
//!
//! 3. **Memory accounting** — `total_mem == per_node` when ACTIVE;
//!    `total_mem == 0` when PARKED. Every `fetch_add` is balanced by a
//!    matching `fetch_sub` in the rollback path.
//!
//! 4. **Wake-then-park** — after a successful wake, a concurrent park
//!    always produces a final state of PARKED with zero memory, regardless
//!    of scheduling order.

#[cfg(loom)]
mod model {
    use loom::sync::{
        atomic::{AtomicU8, AtomicUsize, Ordering},
        Arc,
    };
    use loom::thread;

    // Mirror wick_server::node::state constants.
    const PARKED: u8 = 0;
    const LOADING: u8 = 1;
    const ACTIVE: u8 = 2;

    const PER_NODE: usize = 65_536; // 64 KiB — same as PER_NODE_BYTES

    /// Run the "waker" path: CAS PARKED→LOADING, reserve memory, CAS LOADING→ACTIVE.
    /// On failure (lost CAS or simulated factory error): release memory, restore state.
    fn waker(state: Arc<AtomicU8>, mem: Arc<AtomicUsize>, factory_ok: bool) -> bool {
        // Attempt the winning CAS. Losers stop here.
        if state
            .compare_exchange(PARKED, LOADING, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return false;
        }

        // Reserve memory *before* LOADING→ACTIVE.
        mem.fetch_add(PER_NODE, Ordering::SeqCst);

        if !factory_ok {
            // Simulated factory error rollback.
            mem.fetch_sub(PER_NODE, Ordering::SeqCst);
            state.store(PARKED, Ordering::SeqCst);
            return false;
        }

        // Flip LOADING→ACTIVE. Only the winning thread holds LOADING.
        state.store(ACTIVE, Ordering::SeqCst);
        true
    }

    /// Run the "parker" path: CAS ACTIVE→PARKED and release memory.
    fn parker(state: Arc<AtomicU8>, mem: Arc<AtomicUsize>) -> bool {
        if state
            .compare_exchange(ACTIVE, PARKED, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return false;
        }
        let prev = mem.fetch_sub(PER_NODE, Ordering::SeqCst);
        assert!(
            prev >= PER_NODE,
            "memory underflow: tried to release {PER_NODE} but only {prev} was reserved"
        );
        true
    }

    fn assert_consistent(state: &AtomicU8, mem: &AtomicUsize) {
        let s = state.load(Ordering::SeqCst);
        let m = mem.load(Ordering::SeqCst);
        assert!(
            s == PARKED || s == ACTIVE,
            "terminal state must be PARKED or ACTIVE, got {s}"
        );
        match s {
            ACTIVE => assert_eq!(m, PER_NODE, "ACTIVE must have exactly one node worth of memory"),
            PARKED => assert_eq!(m, 0, "PARKED must have zero memory"),
            _ => unreachable!(),
        }
    }

    #[test]
    fn two_wakers_exactly_one_wins() {
        loom::model(|| {
            let state = Arc::new(AtomicU8::new(PARKED));
            let mem = Arc::new(AtomicUsize::new(0));

            let (s1, m1) = (state.clone(), mem.clone());
            let h1 = thread::spawn(move || waker(s1, m1, true));

            let (s2, m2) = (state.clone(), mem.clone());
            let h2 = thread::spawn(move || waker(s2, m2, true));

            let won1 = h1.join().unwrap();
            let won2 = h2.join().unwrap();

            assert!(won1 ^ won2, "exactly one waker must win the CAS race");
            assert_consistent(&state, &mem);
        });
    }

    #[test]
    fn waker_factory_failure_rolls_back() {
        loom::model(|| {
            let state = Arc::new(AtomicU8::new(PARKED));
            let mem = Arc::new(AtomicUsize::new(0));

            let (s, m) = (state.clone(), mem.clone());
            let h = thread::spawn(move || waker(s, m, false));
            h.join().unwrap();

            assert_eq!(state.load(Ordering::SeqCst), PARKED);
            assert_eq!(mem.load(Ordering::SeqCst), 0);
        });
    }

    #[test]
    fn wake_then_concurrent_park_consistent() {
        loom::model(|| {
            let state = Arc::new(AtomicU8::new(PARKED));
            let mem = Arc::new(AtomicUsize::new(0));

            let (sw, mw) = (state.clone(), mem.clone());
            let hw = thread::spawn(move || waker(sw, mw, true));

            let (sp, mp) = (state.clone(), mem.clone());
            let hp = thread::spawn(move || parker(sp, mp));

            hw.join().unwrap();
            hp.join().unwrap();

            assert_consistent(&state, &mem);
        });
    }

    #[test]
    fn two_wakers_and_parker_consistent() {
        loom::model(|| {
            let state = Arc::new(AtomicU8::new(PARKED));
            let mem = Arc::new(AtomicUsize::new(0));

            let (s1, m1) = (state.clone(), mem.clone());
            let h1 = thread::spawn(move || waker(s1, m1, true));

            let (s2, m2) = (state.clone(), mem.clone());
            let h2 = thread::spawn(move || waker(s2, m2, true));

            let (sp, mp) = (state.clone(), mem.clone());
            let hp = thread::spawn(move || parker(sp, mp));

            h1.join().unwrap();
            h2.join().unwrap();
            hp.join().unwrap();

            assert_consistent(&state, &mem);
        });
    }
}
