//! Background telemetry sampler: one sample per connection per interval,
//! kept in an in-memory ring buffer; also retries failed connections.

use std::time::Duration;

use crate::state::SharedState;

const RECONNECT_EVERY: Duration = Duration::from_secs(30);

pub fn spawn(state: SharedState) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(state.cfg.telemetry.interval_secs.max(1)));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            let slots: Vec<(String, bool, bool)> = {
                let conns = state.connections.read().await;
                conns
                    .iter()
                    .map(|(id, s)| {
                        let due = s.last_attempt.map(|t| t.elapsed() >= RECONNECT_EVERY).unwrap_or(true);
                        (id.clone(), s.driver.is_some(), due)
                    })
                    .collect()
            };
            for (id, connected, reconnect_due) in slots {
                if !connected {
                    if reconnect_due {
                        let st = state.clone();
                        tokio::spawn(async move { st.try_connect(&id).await });
                    }
                    continue;
                }
                let st = state.clone();
                tokio::spawn(async move {
                    let Ok(driver) = st.driver(&id).await else { return };
                    match tokio::time::timeout(Duration::from_secs(10), driver.sample_telemetry()).await {
                        Ok(Ok(sample)) => {
                            let mut t = st.telemetry.write().await;
                            let buf = t.entry(id).or_default();
                            buf.push_back(sample);
                            while buf.len() > st.cfg.telemetry.retention {
                                buf.pop_front();
                            }
                        }
                        Ok(Err(e)) => tracing::debug!(connection = %id, error = %e, "telemetry sample failed"),
                        Err(_) => tracing::debug!(connection = %id, "telemetry sample timed out"),
                    }
                });
            }
        }
    });
}
