.
package playbook.validation

# List of deprecated modules
deprecated_modules = [
    "old_module",
    "legacy_module",
    "deprecated_module_v1",
    "outdated_module"
]

# Deny if a deprecated module is found
deny[msg] {
    is_object(input)
    contains_deprecated_module(input, msg)
}

# Helper function to check if any module is deprecated
contains_deprecated_module(x, msg) {
    is_object(x)
    some key
    x[key].value == deprecated_modules[_]
    msg := sprintf("Deprecated module '%v' found at line '%v'.", [x[key].value, x[key].line])
}

contains_deprecated_module(x, msg) {
    is_array(x)
    some i
    contains_deprecated_module(x[i], msg)
}

contains_deprecated_module(x, msg) {
    is_object(x)
    some key
    contains_deprecated_module(x[key], msg)
}
