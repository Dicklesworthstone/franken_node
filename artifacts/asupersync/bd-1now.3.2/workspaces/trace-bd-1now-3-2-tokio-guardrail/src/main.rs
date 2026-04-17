use tokio::runtime::Builder as TokioBuilder;

fn tokio_guardrail_violations(source: &str) -> Vec<&'static str> {
    let mut violations = Vec::new();
    let compacted: String = source.chars().filter(|ch| !ch.is_whitespace()).collect();

    if !source.contains("new_current_thread") {
        violations.push("missing_current_thread_builder");
    }
    if source.contains("new_multi_thread") {
        violations.push("multi_thread_runtime");
    }
    if compacted.contains("Runtime::new(") || compacted.contains("runtime::Runtime::new(") {
        violations.push("runtime_new");
    }
    if compacted.contains("Handle::current(") || compacted.contains("runtime::Handle::current(") {
        violations.push("runtime_handle_current");
    }
    if source.contains("#[tokio::main") {
        violations.push("tokio_main_macro");
    }
    if source.contains("#[tokio::test") {
        violations.push("tokio_test_macro");
    }
    if source.contains("tokio::spawn") {
        violations.push("tokio_spawn");
    }
    if source.contains("spawn_blocking") {
        violations.push("spawn_blocking");
    }
    if source.contains(".block_on(") {
        violations.push("runtime_block_on");
    }
    if source.contains(".enable_io(") || source.contains(".enable_io()") {
        violations.push("enable_io_runtime");
    }
    if source.contains(".enable_time(") || source.contains(".enable_time()") {
        violations.push("enable_time_runtime");
    }
    if source.contains(".enable_all(") || source.contains(".enable_all()") {
        violations.push("enable_all_runtime");
    }

    violations
}

fn main() {
    let _ = TokioBuilder::new_current_thread();
}

#[cfg(test)]
mod tests {
    use super::tokio_guardrail_violations;

    #[test]
    fn negative_empty_source_reports_missing_current_thread_builder() {
        let violations = tokio_guardrail_violations("");

        assert_eq!(violations, vec!["missing_current_thread_builder"]);
    }

    #[test]
    fn negative_multi_thread_runtime_is_rejected_even_with_current_thread_builder() {
        let source = "TokioBuilder::new_current_thread(); TokioBuilder::new_multi_thread();";

        let violations = tokio_guardrail_violations(source);

        assert!(violations.contains(&"multi_thread_runtime"));
        assert!(!violations.contains(&"missing_current_thread_builder"));
    }

    #[test]
    fn negative_tokio_main_macro_is_rejected() {
        let source = "#[tokio::main]\nasync fn main() { TokioBuilder::new_current_thread(); }";

        let violations = tokio_guardrail_violations(source);

        assert!(violations.contains(&"tokio_main_macro"));
    }

    #[test]
    fn negative_tokio_spawn_is_rejected() {
        let source = "fn run() { TokioBuilder::new_current_thread(); tokio::spawn(async {}); }";

        let violations = tokio_guardrail_violations(source);

        assert!(violations.contains(&"tokio_spawn"));
    }

    #[test]
    fn negative_runtime_block_on_is_rejected() {
        let source =
            "fn run(rt: Runtime) { TokioBuilder::new_current_thread(); rt.block_on(f()); }";

        let violations = tokio_guardrail_violations(source);

        assert!(violations.contains(&"runtime_block_on"));
    }

    #[test]
    fn negative_enable_all_runtime_is_rejected() {
        let source = "fn run() { TokioBuilder::new_current_thread().enable_all(); }";

        let violations = tokio_guardrail_violations(source);

        assert!(violations.contains(&"enable_all_runtime"));
    }

    #[test]
    fn negative_multiple_forbidden_runtime_shapes_are_all_reported() {
        let source =
            "#[tokio::main]\nasync fn main() { tokio::spawn(async {}); Runtime.block_on(f()); }";

        let violations = tokio_guardrail_violations(source);

        assert!(violations.contains(&"missing_current_thread_builder"));
        assert!(violations.contains(&"tokio_main_macro"));
        assert!(violations.contains(&"tokio_spawn"));
        assert!(violations.contains(&"runtime_block_on"));
    }

    #[test]
    fn negative_runtime_new_constructor_is_rejected() {
        let source = "fn run() { TokioBuilder::new_current_thread(); Runtime::new().unwrap(); }";

        let violations = tokio_guardrail_violations(source);

        assert!(violations.contains(&"runtime_new"));
    }

    #[test]
    fn negative_runtime_new_with_obfuscated_path_is_rejected() {
        let source =
            "fn run() { TokioBuilder::new_current_thread(); tokio :: runtime :: Runtime :: new (); }";

        let violations = tokio_guardrail_violations(source);

        assert!(violations.contains(&"runtime_new"));
    }

    #[test]
    fn negative_runtime_handle_current_is_rejected() {
        let source =
            "fn run() { TokioBuilder::new_current_thread(); tokio::runtime::Handle::current(); }";

        let violations = tokio_guardrail_violations(source);

        assert!(violations.contains(&"runtime_handle_current"));
    }

    #[test]
    fn negative_tokio_test_macro_is_rejected() {
        let source = "#[tokio::test]\nasync fn test_case() { TokioBuilder::new_current_thread(); }";

        let violations = tokio_guardrail_violations(source);

        assert!(violations.contains(&"tokio_test_macro"));
    }

    #[test]
    fn negative_spawn_blocking_is_rejected() {
        let source =
            "fn run() { TokioBuilder::new_current_thread(); tokio::task::spawn_blocking(f); }";

        let violations = tokio_guardrail_violations(source);

        assert!(violations.contains(&"spawn_blocking"));
    }

    #[test]
    fn negative_enable_io_runtime_is_rejected() {
        let source = "fn run() { TokioBuilder::new_current_thread().enable_io(); }";

        let violations = tokio_guardrail_violations(source);

        assert!(violations.contains(&"enable_io_runtime"));
    }

    #[test]
    fn negative_enable_time_runtime_is_rejected() {
        let source = "fn run() { TokioBuilder::new_current_thread().enable_time(); }";

        let violations = tokio_guardrail_violations(source);

        assert!(violations.contains(&"enable_time_runtime"));
    }
}
