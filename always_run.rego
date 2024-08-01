.
package playbook.validation


package playbook.validation

# Deny if 'always_run' is found anywhere in the input
deny[msg] {
    some i
    contains_always_run(input[i])
    msg := "Usage of 'always_run' is denied."
}

# Deny if 'become_user: root' is found anywhere in the input
deny[msg] {
    some i
    contains_become_user_root(input[i])
    msg := "Usage of 'become_user: root' is denied."
}

# Helper function to recursively check for 'always_run'
contains_always_run(x) {
    is_object(x)
    some key
    x[key] == true
    key == "always_run"
}

contains_always_run(x) {
    is_array(x)
    some i
    contains_always_run(x[i])
}

contains_always_run(x) {
    is_object(x)
    some key
    contains_always_run(x[key])
}

# Helper function to recursively check for 'become_user: root'
contains_become_user_root(x) {
    is_object(x)
    some key
    x[key] == "root"
    key == "become_user"
}

contains_become_user_root(x) {
    is_array(x)
    some i
    contains_become_user_root(x[i])
}

contains_become_user_root(x) {
    is_object(x)
    some key
    contains_become_user_root(x[key])
}
