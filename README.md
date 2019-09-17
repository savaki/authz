[![GoDoc](https://godoc.org/github.com/savaki/authz?status.svg)](https://godoc.org/github.com/savaki/authz)

auth
-----------------------

```go
package main

import (
  "context"
  "fmt"
  "github.com/savaki/authz"
)

func main() {
    ctx := context.Background()
    authorizer := authz.New("example.com")
    
    fields, ok := authorizer.ReadAccess(ctx, "abc", "agents")
    fmt.Println(fields, ok)
    // ok - true
    // fields - first_name, read_only, user
    
    fields, ok = authorizer.WriteAccess(ctx, "abc", "agents")
    fmt.Println(fields, ok)
    // ok - true
    // fields - first_name, write_only, user
}
```