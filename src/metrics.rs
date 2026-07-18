use std::sync::{Arc, Mutex};

#[derive(Clone, Default)]
pub struct MetricsStore {
    inner: Arc<Mutex<MetricsState>>,
}

#[derive(Default)]
struct MetricsState {
    requests_total: u64,
    errors_total: u64,
    alerts_total: u64,
    auth_requests_total: u64,
    auth_errors_total: u64,
    error_threshold: u64,
}

impl MetricsStore {
    pub fn new_with_threshold(threshold: u64) -> Self {
        let mut state = MetricsState::default();
        state.error_threshold = threshold;
        Self {
            inner: Arc::new(Mutex::new(state)),
        }
    }

    pub fn increment_requests(&self) {
        let mut state = self.inner.lock().unwrap();
        state.requests_total += 1;
    }

    pub fn increment_auth_requests(&self) {
        let mut state = self.inner.lock().unwrap();
        state.auth_requests_total += 1;
    }

    pub fn increment_errors(&self) {
        let mut state = self.inner.lock().unwrap();
        state.errors_total += 1;
        state.auth_errors_total += 1;
        if state.errors_total >= state.error_threshold {
            state.alerts_total += 1;
        }
    }

    pub fn maybe_alert(&self) -> bool {
        let state = self.inner.lock().unwrap();
        state.errors_total >= state.error_threshold
    }

    pub fn alerts_total(&self) -> u64 {
        let state = self.inner.lock().unwrap();
        state.alerts_total
    }

    pub fn render(&self) -> String {
        let state = self.inner.lock().unwrap();
        format!(
            "# HELP auth_requests_total Total number of handled requests\n# TYPE auth_requests_total counter\nauth_requests_total {}\n# HELP auth_auth_requests_total Total number of auth requests\n# TYPE auth_auth_requests_total counter\nauth_auth_requests_total {}\n# HELP auth_errors_total Total number of client/server errors\n# TYPE auth_errors_total counter\nauth_errors_total {}\n# HELP auth_alerts_total Total number of alert events\n# TYPE auth_alerts_total counter\nauth_alerts_total {}\n",
            state.requests_total, state.auth_requests_total, state.errors_total, state.alerts_total
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_store_renders_prometheus_exposition() {
        let metrics = MetricsStore::new_with_threshold(2);
        metrics.increment_requests();
        metrics.increment_requests();
        metrics.increment_errors();

        let rendered = metrics.render();
        assert!(rendered.contains("# HELP auth_requests_total"));
        assert!(rendered.contains("auth_requests_total"));
        assert!(rendered.contains("auth_errors_total"));
    }
}
