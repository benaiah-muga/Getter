//! A deliberately capability-free Wasmtime execution sandbox.
//!
//! Getter's `getter.abi.v1` workloads import nothing. There is no WASI context,
//! no preopened directory, no socket capability, no environment, and no
//! argument vector exposed to a task. The only host interaction is copying task
//! input bytes into guest memory and copying a bounded output slice back.
//!
//! CPU is bounded both by deterministic fuel metering and by a wall-clock epoch
//! deadline, because fuel accounting depends on the configured budget rather
//! than real time and a hostile module can consume memory bandwidth without
//! executing many instructions. Linear memory, table, and instance counts are
//! bounded by [`wasmtime::StoreLimits`].
//!
//! Wasm is a security boundary only when Wasmtime and the embedding are
//! correct. This sandbox is defense in depth, not a proof that arbitrary Wasm is
//! safe. Operators should keep their Getter/worker build current.

#![deny(unsafe_code)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use wasmtime::OptLevel;
use wasmtime::{
    Config, Engine, Instance, Module, Store, StoreLimits, StoreLimitsBuilder, UpdateDeadline,
};

/// Epoch ticker resolution. Wall-clock deadlines are approximate to this
/// granularity plus scheduling latency.
pub const EPOCH_TICK: Duration = Duration::from_millis(10);
pub const MAX_WASM_STACK_BYTES: usize = 1024 * 1024;
const COMPILED_MODULE_CACHE_ENTRIES: usize = 8;

#[derive(Debug, Clone)]
pub struct SandboxLimits {
    pub max_module_bytes: usize,
    pub max_input_bytes: usize,
    pub max_memory_bytes: u64,
    pub max_output_bytes: u64,
    pub max_fuel: u64,
    pub max_timeout: Duration,
}

impl Default for SandboxLimits {
    fn default() -> Self {
        Self {
            max_module_bytes: getter_protocol::MAX_ARTIFACT_BYTES,
            max_input_bytes: getter_protocol::MAX_INPUT_BYTES,
            max_memory_bytes: 256 * 1024 * 1024,
            max_output_bytes: getter_protocol::MAX_OUTPUT_BYTES,
            max_fuel: getter_protocol::MAX_FUEL,
            max_timeout: Duration::from_secs(getter_protocol::MAX_TASK_TIMEOUT_SECS),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ExecutionRequest {
    pub input: Vec<u8>,
    pub memory_bytes: u64,
    pub output_bytes: u64,
    pub timeout: Duration,
    pub fuel: u64,
    /// Cooperative cancellation set by the worker for pause/job cancellation.
    pub cancel: Arc<AtomicBool>,
}

#[derive(Debug)]
pub struct ExecutionResult {
    pub output: Vec<u8>,
    pub fuel_used: u64,
    pub elapsed_ms: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    #[error("workload artifact is too large")]
    ModuleTooLarge,
    #[error("workload input is too large")]
    InputTooLarge,
    #[error("workload artifact is not a WebAssembly module")]
    InvalidModule,
    #[error("workload imports {0} host function(s); getter.abi.v1 forbids all imports")]
    ImportsForbidden(usize),
    #[error("workload is missing required export: {0}")]
    MissingExport(&'static str),
    #[error("requested memory limit exceeds the sandbox maximum")]
    MemoryLimitRequested,
    #[error("requested timeout exceeds the sandbox maximum")]
    TimeoutRequested,
    #[error("requested fuel exceeds the sandbox maximum")]
    FuelRequested,
    #[error("requested output limit exceeds the sandbox maximum")]
    OutputRequested,
    #[error("workload exceeded its memory limit")]
    MemoryLimit,
    #[error("workload exhausted its fuel budget")]
    FuelExhausted,
    #[error("workload exceeded its wall-clock deadline")]
    Timeout,
    #[error("workload execution was cancelled")]
    Cancelled,
    #[error("workload produced {actual} bytes, above the {limit} byte limit")]
    OutputTooLarge { actual: u64, limit: u64 },
    #[error("workload returned an invalid output region (pointer {pointer}, length {length}, memory {memory})")]
    InvalidOutputRegion {
        pointer: u32,
        length: u32,
        memory: usize,
    },
    #[error("workload trapped: {0}")]
    Trap(String),
    #[error("execution task failed: {0}")]
    Execution(String),
}

pub struct Sandbox {
    engine: Engine,
    limits: SandboxLimits,
    stop_ticker: Arc<AtomicBool>,
    ticker: Option<std::thread::JoinHandle<()>>,
    compiled_modules: Mutex<HashMap<String, Arc<Module>>>,
}

impl std::fmt::Debug for Sandbox {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Sandbox")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl Sandbox {
    pub fn new(limits: SandboxLimits) -> Result<Self, RuntimeError> {
        let mut config = Config::new();
        config.consume_fuel(true);
        config.epoch_interruption(true);
        // Fast compilation is sufficient for local workloads and reduces the
        // worker's attack surface for compile-time resource use.
        config.cranelift_opt_level(OptLevel::Speed);
        config.max_wasm_stack(MAX_WASM_STACK_BYTES);
        let engine = Engine::new(&config)
            .map_err(|error| RuntimeError::Execution(format!("engine creation failed: {error}")))?;
        let stop_ticker = Arc::new(AtomicBool::new(false));
        let ticker_flag = Arc::clone(&stop_ticker);
        let ticker_engine = engine.clone();
        let ticker = std::thread::Builder::new()
            .name("getter-epoch".into())
            .spawn(move || {
                while !ticker_flag.load(Ordering::Relaxed) {
                    std::thread::sleep(EPOCH_TICK);
                    ticker_engine.increment_epoch();
                }
            })
            .map_err(|error| RuntimeError::Execution(format!("ticker thread: {error}")))?;
        Ok(Self {
            engine,
            limits,
            stop_ticker,
            ticker: Some(ticker),
            compiled_modules: Mutex::new(HashMap::new()),
        })
    }

    pub fn limits(&self) -> &SandboxLimits {
        &self.limits
    }

    /// Execute one task instance. The caller normally invokes this from a
    /// blocking worker thread; it never calls back into async code.
    pub fn execute(
        &self,
        artifact: &[u8],
        request: &ExecutionRequest,
    ) -> Result<ExecutionResult, RuntimeError> {
        self.validate_limits(request)?;
        if artifact.len() > self.limits.max_module_bytes {
            return Err(RuntimeError::ModuleTooLarge);
        }
        if !artifact.starts_with(b"\0asm") {
            return Err(RuntimeError::InvalidModule);
        }
        let module = self.compiled_module(artifact)?;

        let timeout = request.timeout.min(self.limits.max_timeout);
        let limits = StoreLimitsBuilder::new()
            .memory_size(usize::try_from(request.memory_bytes).unwrap_or(usize::MAX))
            .instances(1)
            .memories(1)
            .tables(2)
            .table_elements(100_000)
            .trap_on_grow_failure(true)
            .build();
        let mut store = Store::new(&self.engine, limits);
        store.limiter(|limits| limits);
        store
            .set_fuel(request.fuel)
            .map_err(|error| RuntimeError::Execution(error.to_string()))?;
        let started = Instant::now();
        let cancel = Arc::clone(&request.cancel);
        store.epoch_deadline_callback(move |_context| {
            if cancel.load(Ordering::Relaxed) {
                return Err(wasmtime::Error::msg(
                    "getter execution cancelled by worker policy",
                ));
            }
            if started.elapsed() >= timeout {
                return Err(wasmtime::Error::msg("getter execution deadline exceeded"));
            }
            Ok(UpdateDeadline::Continue(2))
        });
        store.set_epoch_deadline(2);

        let result = self.run_instance(&module, &mut store, request);
        let elapsed_ms = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
        let fuel_used = request.fuel.saturating_sub(store.get_fuel().unwrap_or(0));
        match result {
            Ok(output) => Ok(ExecutionResult {
                output,
                fuel_used,
                elapsed_ms,
            }),
            Err(error) => Err(classify_execution_error(error, elapsed_ms)),
        }
    }

    fn compiled_module(&self, artifact: &[u8]) -> Result<Arc<Module>, RuntimeError> {
        use sha2::{Digest, Sha256};
        let digest = format!("{:x}", Sha256::digest(artifact));
        if let Ok(cache) = self.compiled_modules.lock() {
            if let Some(module) = cache.get(&digest) {
                return Ok(Arc::clone(module));
            }
        }
        let module = Module::new(&self.engine, artifact).map_err(|error| {
            let text = format!("{error:#}");
            if text.contains("magic") || text.contains("version") {
                RuntimeError::InvalidModule
            } else {
                RuntimeError::Trap(bound(&text))
            }
        })?;
        let import_count = module.imports().count();
        if import_count > 0 {
            return Err(RuntimeError::ImportsForbidden(import_count));
        }
        for required in ["memory", "getter_alloc", "getter_execute"] {
            if module.get_export(required).is_none() {
                return Err(RuntimeError::MissingExport(required));
            }
        }
        let module = Arc::new(module);
        if let Ok(mut cache) = self.compiled_modules.lock() {
            if cache.len() >= COMPILED_MODULE_CACHE_ENTRIES {
                cache.clear();
            }
            cache.insert(digest, Arc::clone(&module));
        }
        Ok(module)
    }

    fn validate_limits(&self, request: &ExecutionRequest) -> Result<(), RuntimeError> {
        if request.input.len() > self.limits.max_input_bytes
            || request.input.len() > getter_protocol::MAX_INPUT_BYTES
        {
            return Err(RuntimeError::InputTooLarge);
        }
        if request.memory_bytes == 0 || request.memory_bytes > self.limits.max_memory_bytes {
            return Err(RuntimeError::MemoryLimitRequested);
        }
        if request.timeout.is_zero() || request.timeout > self.limits.max_timeout {
            return Err(RuntimeError::TimeoutRequested);
        }
        if request.fuel == 0 || request.fuel > self.limits.max_fuel {
            return Err(RuntimeError::FuelRequested);
        }
        if request.output_bytes == 0 || request.output_bytes > self.limits.max_output_bytes {
            return Err(RuntimeError::OutputRequested);
        }
        Ok(())
    }

    fn run_instance(
        &self,
        module: &Arc<Module>,
        store: &mut Store<StoreLimits>,
        request: &ExecutionRequest,
    ) -> Result<Vec<u8>, RuntimeError> {
        let instance = Instance::new(&mut *store, module, &[])
            .map_err(|error| RuntimeError::Trap(bound(&format!("{error:#}"))))?;
        let memory = instance
            .get_memory(&mut *store, "memory")
            .ok_or(RuntimeError::MissingExport("memory"))?;
        let alloc = instance
            .get_typed_func::<u32, u32>(&mut *store, "getter_alloc")
            .map_err(|_| RuntimeError::MissingExport("getter_alloc"))?;
        let execute = instance
            .get_typed_func::<(u32, u32), u64>(&mut *store, "getter_execute")
            .map_err(|_| RuntimeError::MissingExport("getter_execute"))?;

        let pointer = alloc
            .call(&mut *store, request.input.len() as u32)
            .map_err(|error| RuntimeError::Trap(bound(&format!("{error:#}"))))?;
        if !request.input.is_empty() {
            let start = pointer as usize;
            let end = start
                .checked_add(request.input.len())
                .ok_or(RuntimeError::InputTooLarge)?;
            let data = memory.data_mut(&mut *store);
            let region = data.get_mut(start..end).ok_or_else(|| {
                RuntimeError::Trap("workload allocation lies outside linear memory".into())
            })?;
            region.copy_from_slice(&request.input);
        }
        let packed = execute
            .call(&mut *store, (pointer, request.input.len() as u32))
            .map_err(|error| RuntimeError::Trap(bound(&format!("{error:#}"))))?;
        let output_pointer = (packed >> 32) as u32;
        let output_length = packed as u32;
        if u64::from(output_length) > request.output_bytes {
            return Err(RuntimeError::OutputTooLarge {
                actual: u64::from(output_length),
                limit: request.output_bytes,
            });
        }
        let memory_size = memory.data_size(&mut *store);
        let start = output_pointer as usize;
        let end =
            start
                .checked_add(output_length as usize)
                .ok_or(RuntimeError::InvalidOutputRegion {
                    pointer: output_pointer,
                    length: output_length,
                    memory: memory_size,
                })?;
        if end > memory_size {
            return Err(RuntimeError::InvalidOutputRegion {
                pointer: output_pointer,
                length: output_length,
                memory: memory_size,
            });
        }
        Ok(memory.data(&mut *store)[start..end].to_vec())
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        self.stop_ticker.store(true, Ordering::Relaxed);
        if let Some(ticker) = self.ticker.take() {
            let _ = ticker.join();
        }
    }
}

fn classify_execution_error(error: RuntimeError, _elapsed_ms: u64) -> RuntimeError {
    if let RuntimeError::Trap(text) = &error {
        let lower = text.to_ascii_lowercase();
        if lower.contains("fuel") {
            return RuntimeError::FuelExhausted;
        }
        if lower.contains("cancelled") {
            return RuntimeError::Cancelled;
        }
        if lower.contains("epoch") || lower.contains("interrupt") || lower.contains("deadline") {
            return RuntimeError::Timeout;
        }
        if lower.contains("memory") && (lower.contains("limit") || lower.contains("grow")) {
            return RuntimeError::MemoryLimit;
        }
    }
    error
}

fn bound(text: &str) -> String {
    let mut bounded = text.chars().take(600).collect::<String>();
    if text.chars().count() > 600 {
        bounded.push('…');
    }
    bounded
}

/// Compile-time validation useful for rejecting artifacts before a lease.
pub fn validate_artifact(
    engine: &Engine,
    artifact: &[u8],
    max_module_bytes: usize,
) -> Result<(), RuntimeError> {
    if artifact.len() > max_module_bytes {
        return Err(RuntimeError::ModuleTooLarge);
    }
    if !artifact.starts_with(b"\0asm") {
        return Err(RuntimeError::InvalidModule);
    }
    let module = Module::new(engine, artifact)
        .map_err(|error| RuntimeError::Trap(bound(&format!("{error:#}"))))?;
    let imports = module.imports().count();
    if imports > 0 {
        return Err(RuntimeError::ImportsForbidden(imports));
    }
    for required in ["memory", "getter_alloc", "getter_execute"] {
        if module.get_export(required).is_none() {
            return Err(RuntimeError::MissingExport(required));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sandbox() -> Sandbox {
        Sandbox::new(SandboxLimits::default()).expect("sandbox")
    }

    fn request(timeout_ms: u64, fuel: u64) -> ExecutionRequest {
        ExecutionRequest {
            input: b"hello".to_vec(),
            memory_bytes: 16 * 1024 * 1024,
            output_bytes: 1024,
            timeout: Duration::from_millis(timeout_ms),
            fuel,
            cancel: Arc::new(AtomicBool::new(false)),
        }
    }

    fn hello_module() -> Vec<u8> {
        wat::parse_str(
            r#"
            (module
              (memory (export "memory") 1)
              (func (export "getter_alloc") (param i32) (result i32)
                i32.const 1024)
              (func (export "getter_execute") (param i32 i32) (result i64)
                i64.const 4398046511109)
              (data (i32.const 1024) "hello"))
            "#,
        )
        .expect("wat")
    }

    #[test]
    fn executes_capability_free_module_and_copies_output() {
        let sandbox = sandbox();
        let result = sandbox
            .execute(&hello_module(), &request(2_000, 10_000_000))
            .expect("execute");
        assert_eq!(result.output, b"hello");
        assert!(result.fuel_used > 0);
    }

    #[test]
    fn rejects_imports() {
        let module = wat::parse_str(
            r#"
            (module
              (import "wasi_snapshot_preview1" "fd_write"
                (func $write (param i32 i32 i32 i32) (result i32)))
              (memory (export "memory") 1)
              (func (export "getter_alloc") (param i32) (result i32) i32.const 0)
              (func (export "getter_execute") (param i32 i32) (result i64) i64.const 0))
            "#,
        )
        .expect("wat");
        let error = sandbox()
            .execute(&module, &request(1_000, 1_000_000))
            .expect_err("imports must be rejected");
        assert!(matches!(error, RuntimeError::ImportsForbidden(1)));
    }

    #[test]
    fn enforces_fuel_and_wall_clock_limits() {
        let module = wat::parse_str(
            r#"
            (module
              (memory (export "memory") 1)
              (func (export "getter_alloc") (param i32) (result i32) i32.const 0)
              (func (export "getter_execute") (param i32 i32) (result i64)
                (loop $forever br $forever)
                i64.const 0))
            "#,
        )
        .expect("wat");
        let fuel_error = sandbox()
            .execute(&module, &request(5_000, 10_000))
            .expect_err("fuel");
        assert!(
            matches!(fuel_error, RuntimeError::FuelExhausted),
            "{fuel_error:?}"
        );
        let timeout_error = sandbox()
            .execute(&module, &request(80, 10_000_000_000))
            .expect_err("timeout");
        assert!(
            matches!(timeout_error, RuntimeError::Timeout),
            "{timeout_error:?}"
        );
    }

    #[test]
    fn enforces_memory_limit_at_instantiation_or_growth() {
        let module = wat::parse_str(
            r#"
            (module
              (memory (export "memory") 64)
              (func (export "getter_alloc") (param i32) (result i32) i32.const 0)
              (func (export "getter_execute") (param i32 i32) (result i64) i64.const 0))
            "#,
        )
        .expect("wat");
        let mut request = request(1_000, 1_000_000);
        request.memory_bytes = 1024 * 1024;
        let error = sandbox().execute(&module, &request).expect_err("memory");
        assert!(
            matches!(error, RuntimeError::MemoryLimit | RuntimeError::Trap(_)),
            "{error:?}"
        );
    }

    #[test]
    fn enforces_output_limit_and_bounds() {
        let module = wat::parse_str(
            r#"
            (module
              (memory (export "memory") 1)
              (func (export "getter_alloc") (param i32) (result i32) i32.const 0)
              (func (export "getter_execute") (param i32 i32) (result i64)
                i64.const 4294967396))
            "#,
        )
        .expect("wat");
        let mut output_request = request(1_000, 1_000_000);
        output_request.output_bytes = 4;
        let error = sandbox()
            .execute(&module, &output_request)
            .expect_err("output");
        assert!(matches!(
            error,
            RuntimeError::OutputTooLarge { actual: 100, .. }
        ));

        let bad_bounds = wat::parse_str(
            r#"
            (module
              (memory (export "memory") 1)
              (func (export "getter_alloc") (param i32) (result i32) i32.const 0)
              (func (export "getter_execute") (param i32 i32) (result i64)
                i64.const 281470681743460))
            "#,
        )
        .expect("wat");
        let error = sandbox()
            .execute(&bad_bounds, &request(1_000, 1_000_000))
            .expect_err("bounds");
        assert!(
            matches!(error, RuntimeError::InvalidOutputRegion { .. }),
            "{error:?}"
        );
    }

    #[test]
    fn rejects_oversized_inputs_and_artifacts() {
        let sandbox = sandbox();
        let mut oversized = request(1_000, 1_000_000);
        oversized.input = vec![0; 1024 * 1024 + 1];
        assert!(matches!(
            sandbox.execute(&hello_module(), &oversized),
            Err(RuntimeError::InputTooLarge)
        ));
        assert!(matches!(
            sandbox.execute(&vec![0; 1024], &request(1_000, 1_000_000)),
            Err(RuntimeError::InvalidModule)
        ));
        assert!(matches!(
            sandbox.execute(&Vec::new(), &request(1_000, 1_000_000)),
            Err(RuntimeError::InvalidModule)
        ));
    }

    #[test]
    fn missing_exports_are_rejected_before_execution() {
        let module = wat::parse_str(
            r#"
            (module
              (memory (export "memory") 1)
              (func (export "getter_alloc") (param i32) (result i32) i32.const 0))
            "#,
        )
        .expect("wat");
        assert!(matches!(
            sandbox().execute(&module, &request(1_000, 1_000_000)),
            Err(RuntimeError::MissingExport("getter_execute"))
        ));
    }

    #[test]
    fn cooperative_cancellation_interrupts_a_running_loop() {
        let module = wat::parse_str(
            r#"
            (module
              (memory (export "memory") 1)
              (func (export "getter_alloc") (param i32) (result i32) i32.const 0)
              (func (export "getter_execute") (param i32 i32) (result i64)
                (loop $forever br $forever)
                i64.const 0))
            "#,
        )
        .expect("wat");
        let request = request(5_000, 10_000_000_000);
        let cancel = Arc::clone(&request.cancel);
        let handle = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(120));
            cancel.store(true, Ordering::Relaxed);
        });
        let error = sandbox().execute(&module, &request).expect_err("cancelled");
        handle.join().expect("canceller");
        assert!(matches!(error, RuntimeError::Cancelled), "{error:?}");
    }

    #[test]
    fn sandbox_limits_cannot_be_exceeded_by_requests() {
        let sandbox = Sandbox::new(SandboxLimits {
            max_memory_bytes: 1024 * 1024,
            max_timeout: Duration::from_millis(100),
            ..SandboxLimits::default()
        })
        .expect("sandbox");
        let module = hello_module();
        let mut too_much_memory = request(50, 1_000_000);
        too_much_memory.memory_bytes = 2 * 1024 * 1024;
        assert!(matches!(
            sandbox.execute(&module, &too_much_memory),
            Err(RuntimeError::MemoryLimitRequested)
        ));
        let mut too_slow = request(2_000, 1_000_000);
        too_slow.memory_bytes = 1024 * 1024;
        assert!(matches!(
            sandbox.execute(&module, &too_slow),
            Err(RuntimeError::TimeoutRequested)
        ));
    }
}
