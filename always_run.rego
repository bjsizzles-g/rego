.
package playbook.validation

deny[msg] {
    # Check tasks directly under input
    some i
    input.tasks[i].always_run == true
    msg := sprintf("Usage of 'always_run' is denied in task %v.", [i])
}

deny[msg] {
    # Check tasks within roles
    some r
    some t
    input.roles[r].tasks[t].always_run == true
    msg := sprintf("Usage of 'always_run' is denied in role %v, task %v.", [r, t])
}

deny[msg] {
    # Check tasks in roles with nested dictionaries or lists
    some r
    role_tasks := input.roles[r].tasks
    some i
    role_tasks[i].always_run == true
    msg := sprintf("Usage of 'always_run' is denied in role %v, nested task %v.", [r, i])
}
