package auth

# helper rule to determine what roles the current user belongs to
role[name] {
	data.role_mappings[name][input.uid]
}

# determine which fields user has read access to
read_access[field_name] {
	some role_name
    some index
    role[role_name] # find all matching roles
    data.permissions[role_name][input.resource].fields[index].name = field_name # find all fields that match
    data.permissions[role_name][input.resource].fields[index].read = true       # where we have read access
}

# determine which fields user has write access to
write_access[field_name] {
	some role_name
    some index
    role[role_name] # find all matching roles
    data.permissions[role_name][input.resource].fields[index].name = field_name # find all fields that match
    data.permissions[role_name][input.resource].fields[index].write = true      # where we have write access
}

# is the current user allowed to read the resource?
default allow_read = false
allow_read {
	count(read_access) > 0
}

# is the current user allowed to write to the resource?
default allow_write = false
allow_write {
	count(write_access) > 0
}
