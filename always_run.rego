package main

deny[msg] {
    task := input.tasks[_]
    task.always_run
    msg = sprintf("always_run is not allowed in task '%s'. Use check_mode instead.", [task.name])
}
