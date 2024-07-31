package always_run

# Entry point for the policy
deny[{"message": msg}] {
    # Check if the input has the 'always_run' key
    input.always_run != null
    msg := "always_run is not allowed, instead use check_mode."
}
