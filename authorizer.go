package authz

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage/inmem"
	"golang.org/x/sync/errgroup"
)

const (
	defaultInterval = time.Minute
)

type query struct {
	read  rego.PartialResult
	write rego.PartialResult
}

type Authorizer struct {
	cancel context.CancelFunc
	ready  chan struct{}
	done   chan struct{}

	mutex sync.Mutex
	query query
}

func (a *Authorizer) checkAccess(ctx context.Context, partial rego.PartialResult, uid, resource string) ([]string, bool) {
	input := map[string]interface{}{
		"uid":      uid,
		"resource": resource,
	}

	r := partial.Rego(
		rego.Input(input),
	)

	result, err := r.Eval(ctx)
	if err != nil {
		fmt.Printf("eval failed: %v", err)
		return nil, false
	}

	// expect exactly one result back
	if len(result) != 1 || len(result[0].Expressions) != 1 {
		return nil, false
	}

	// unpack result into a string slice of fields
	raw := result[0].Expressions[0].Value
	slice, ok := raw.([]interface{})
	if !ok {
		return nil, false
	}

	var fields []string
	for _, item := range slice {
		field, ok := item.(string)
		if ok {
			fields = append(fields, field)
		}
	}

	sort.Strings(fields)
	return fields, len(fields) > 0
}

// ReadAccess accepts a user and a resource and returns (a) which fields the user can read
// (nil for all fields) and (b) whether read access is allowed
func (a *Authorizer) ReadAccess(ctx context.Context, uid, resource string) ([]string, bool) {
	<-a.ready

	a.mutex.Lock()
	partial := a.query.read
	a.mutex.Unlock()

	return a.checkAccess(ctx, partial, uid, resource)
}

// WriteAccess accepts a user and a resource and returns (a) which fields the user can write
// (nil for all fields) and (b) whether write access is allowed
func (a *Authorizer) WriteAccess(ctx context.Context, uid, resource string) ([]string, bool) {
	<-a.ready

	a.mutex.Lock()
	partial := a.query.write
	a.mutex.Unlock()

	return a.checkAccess(ctx, partial, uid, resource)
}

func (a *Authorizer) mainLoop(ctx context.Context, site string, config config) {
	defer close(a.done)

	ticker := time.NewTicker(config.interval)
	defer ticker.Stop()

	for {
		if query, err := pollOnce(ctx, site, config); err != nil {
			fmt.Println(err)

		} else {
			a.mutex.Lock()
			a.query = query
			a.mutex.Unlock()

			select {
			case <-a.ready:
			default:
				close(a.ready)
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Stop the background polling
func (a *Authorizer) Stop() {
	a.cancel()
	<-a.done
}

func New(site string, opts ...Option) *Authorizer {
	options := buildOptions(opts...)
	ctx, cancel := context.WithCancel(context.Background())
	authorizer := &Authorizer{
		cancel: cancel,
		done:   make(chan struct{}),
		ready:  make(chan struct{}),
	}
	go authorizer.mainLoop(ctx, site, options)

	return authorizer
}

func pollOnce(ctx context.Context, site string, config config) (query, error) {
	var (
		data   map[string]interface{}
		module string
	)

	group, child := errgroup.WithContext(ctx)
	group.Go(func() error {
		v, err := config.data(child, site)
		if err != nil {
			return err
		}
		data = v
		return nil
	})
	group.Go(func() error {
		v, err := config.module(child, site)
		if err != nil {
			return err
		}
		module = v
		return nil
	})
	if err := group.Wait(); err != nil {
		return query{}, err
	}

	store := inmem.NewFromObject(data)
	read := rego.New(
		rego.Query("data.auth.read_access"),
		rego.Module("auth", module),
		rego.Store(store),
	)
	partialRead, err := read.PartialEval(ctx)
	if err != nil {
		return query{}, fmt.Errorf("partial eval failed for authorizer: %v", err)
	}

	write := rego.New(
		rego.Query("data.auth.write_access"),
		rego.Module("auth", module),
		rego.Store(store),
	)
	partialWrite, err := write.PartialEval(ctx)
	if err != nil {
		return query{}, fmt.Errorf("partial eval failed for authorizer: %v", err)
	}

	return query{
		read:  partialRead,
		write: partialWrite,
	}, nil
}
