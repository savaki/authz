package authz

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// DataFunc dynamically retrieve data for a given site e.g. api.example.com
type DataFunc func(ctx context.Context, site string) (map[string]interface{}, error)

// ModuleFunc dynamically retrieves the module for a given site e.g. api.example.com
type ModuleFunc func(ctx context.Context, site string) (string, error)

// Option provides functional options
type Option func(c *config)

type config struct {
	data     DataFunc
	interval time.Duration
	module   ModuleFunc
}

func buildOptions(opts ...Option) config {
	c := config{
		data:     defaultData,
		interval: defaultInterval,
		module:   defaultModule,
	}

	for _, opt := range opts {
		opt(&c)
	}

	return c
}

// WithData allows the data source for each site to be customized
func WithData(fn DataFunc) Option {
	return func(c *config) {
		c.data = fn
	}
}

// WithDataURL reads the data for the site from a fix static url
func WithDataURL(url string) Option {
	var data map[string]interface{}
	resp, err := http.Get(url)
	if err == nil {
		defer resp.Body.Close()
		err = json.NewDecoder(resp.Body).Decode(&data)
	}

	return func(c *config) {
		c.data = func(ctx context.Context, site string) (map[string]interface{}, error) {
			if err != nil {
				return nil, err
			}

			return data, nil
		}
	}
}

// WithInterval polls the site at the requested interval
func WithInterval(t time.Duration) Option {
	return func(c *config) {
		c.interval = t
	}
}

// WithModule provides a dynamic per site lookup for module info
func WithModule(fn ModuleFunc) Option {
	return func(c *config) {
		c.module = fn
	}
}

// WithStaticModule provides a static module definition
func WithStaticModule(module string) Option {
	return func(c *config) {
		c.module = func(ctx context.Context, site string) (string, error) {
			return module, nil
		}
	}
}

// WithStaticData provides static data
func WithStaticData(data map[string]interface{}) Option {
	return func(c *config) {
		c.data = func(ctx context.Context, site string) (map[string]interface{}, error) {
			return data, nil
		}
	}
}

func defaultModule(ctx context.Context, site string) (string, error) {
	return "", nil
}

func defaultData(ctx context.Context, site string) (map[string]interface{}, error) {
	return nil, nil
}
