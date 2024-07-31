package yaml.check

# Input will be a YAML file parsed into JSON
deny[msg] {
    # Check if 'always_run' key is present in the input
    input.always_run

    # Define the denial message
    msg := "always_run is not allowed, instead use check_mode"
}
