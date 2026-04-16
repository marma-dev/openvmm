struct InitializedVm {
    // ... existing fields ...
    driver_source: VmTaskDriverSource,
    boot_start_instant: std::time::Instant,
}

impl InitializedVm {
    fn new_with_hypervisor() -> Self {
        let boot_start_instant = std::time::Instant::now();
        // ... existing code ...
        Ok(Self { 
            // ... existing fields ...
            driver_source,
            boot_start_instant,
        })
    }

    fn load(self) {
        let Self { 
            // ... existing fields ...
            driver_source,
            boot_start_instant,
        } = self;
    }
}

struct LoadedVm {
    // ... existing fields ...
    running: bool,
    boot_start_instant: Option<std::time::Instant>,
}

impl LoadedVm {
    async fn load() {
        // ... existing code ...
        LoadedVm { 
            // ... existing fields ...
            running: false,
            boot_start_instant: Some(boot_start_instant),
        }
    }

    async fn resume(&mut self) -> bool {
        if self.running {
            return false;
        }
        if let Some(boot_start) = self.boot_start_instant.take() {
            let boot_time = boot_start.elapsed();
            tracing::info!(
                boot_time_ms = (boot_time.as_secs_f64() * 1000.0) as u64,
                boot_time = %format!("{:.1?}", boot_time),
                "starting VM"
            );
        }
        self.state_units.start().await;
        self.running = true;
        true
    }
}