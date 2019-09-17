package authz

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"testing"

	"github.com/tj/assert"
)

func TestAuthorizer_ReadAccess(t *testing.T) {
	content, err := ioutil.ReadFile("testdata/data.json")
	assert.Nil(t, err)

	var data map[string]interface{}
	err = json.Unmarshal(content, &data)
	assert.Nil(t, err)

	content, err = ioutil.ReadFile("testdata/module.rego")
	assert.Nil(t, err)
	module := string(content)

	ctx := context.Background()
	authorizer := New("example.com", WithStaticData(data), WithStaticModule(module))

	t.Run("read", func(t *testing.T) {
		fields, ok := authorizer.ReadAccess(ctx, "abc", "agents")
		assert.True(t, ok)
		assert.Equal(t, []string{"first_name", "read_only", "user"}, fields)
	})

	t.Run("write", func(t *testing.T) {
		fields, ok := authorizer.WriteAccess(ctx, "abc", "agents")
		assert.True(t, ok)
		assert.Equal(t, []string{"first_name", "user", "write_only"}, fields)
	})
}

func TestAuthorizer_Defaults(t *testing.T) {
	ctx := context.Background()
	authorizer := New("example.com")

	t.Run("read", func(t *testing.T) {
		fields, ok := authorizer.ReadAccess(ctx, "abc", "agents")
		assert.True(t, ok)
		assert.Equal(t, []string{"first_name", "read_only", "user"}, fields)
	})

	t.Run("write", func(t *testing.T) {
		fields, ok := authorizer.WriteAccess(ctx, "abc", "agents")
		assert.True(t, ok)
		assert.Equal(t, []string{"first_name", "user", "write_only"}, fields)
	})
}

func BenchmarkAuthorizer(t *testing.B) {
	content, err := ioutil.ReadFile("testdata/data.json")
	assert.Nil(t, err)

	var data map[string]interface{}
	err = json.Unmarshal(content, &data)
	assert.Nil(t, err)

	content, err = ioutil.ReadFile("testdata/module.rego")
	assert.Nil(t, err)
	module := string(content)

	ctx := context.Background()
	authorizer := New("example.com", WithStaticData(data), WithStaticModule(module))

	for i := 0; i < t.N; i++ {
		_, ok := authorizer.ReadAccess(ctx, "abc", "agents")
		if !ok {
			t.Fatalf("got false; want true")
		}
	}
}
