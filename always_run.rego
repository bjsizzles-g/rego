
package playbook.validation

deny[msg] {
    # Check tasks directly under input
    some i
    input.tasks[i].always_run == true
    msg := "Usage of 'always_run' is denied in task " + tostring(i) + "."
}

deny[msg] {
    # Check tasks within roles
    some r
    some t
    input.roles[r].tasks[t].always_run == true
    msg := "Usage of 'always_run' is denied in role " + tostring(r) + ", task " + tostring(t) + "."
}

deny[msg] {
    # Check tasks in roles with nested dictionaries or lists
    some r
    role_tasks := input.roles[r].tasks
    some i
    role_tasks[i].always_run == true
    msg := "Usage of 'always_run' is denied in role " + tostring(r) + ", nested task " + tostring(i) + "."
}
