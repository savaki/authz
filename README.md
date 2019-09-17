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
    // fields - list of fields with read access
    
    fields, ok = authorizer.WriteAccess(ctx, "abc", "agents")
    fmt.Println(fields, ok)
    // ok - true
    // fields - list of fields with write access
}
```