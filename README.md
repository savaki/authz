auth
-----------------------

```go
func example() {
    ctx := context.Background()
    authorizer := New("example.com")
    
    fields, ok := authorizer.ReadAccess(ctx, "abc", "agents")
    // ok - true
    // fields - list of fields with read access
    
    fields, ok = authorizer.WriteAccess(ctx, "abc", "agents")
    // ok - true
    // fields - list of fields with write access
}
```