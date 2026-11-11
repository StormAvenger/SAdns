// Command schemagen writes the JSON Schema for SAdns reports, derived by
// reflection from model.Report so it cannot drift from the code:
//
//	go run ./tools/schemagen > docs/schema/report.schema.json
//
// A test fails if the committed schema is out of date.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/StormAvenger/SAdns/internal/model"
)

func main() {
	b, err := Generate()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Stdout.Write(b)
}

// Generate returns the indented schema document.
func Generate() ([]byte, error) {
	g := &gen{defs: map[string]any{}}
	root := g.object(reflect.TypeOf(model.Report{}))
	doc := map[string]any{
		"$schema":     "https://json-schema.org/draft/2020-12/schema",
		"$id":         "https://github.com/StormAvenger/SAdns/docs/schema/report.schema.json",
		"title":       "SAdns report",
		"description": "Report produced by SAdns (schema string sadns/report/v1). Fields may be added in minor versions; consumers must ignore unknown fields. Breaking changes bump the schema string.",
		"$defs":       g.defs,
	}
	for k, v := range root {
		doc[k] = v
	}
	doc["properties"].(map[string]any)["schema"] = map[string]any{"type": "string", "pattern": "^sadns/report/v1$"}
	b, err := json.MarshalIndent(doc, "", "  ")
	return append(b, '\n'), err
}

type gen struct{ defs map[string]any }

func (g *gen) schema(t reflect.Type) map[string]any {
	if t == reflect.TypeOf(time.Time{}) {
		return map[string]any{"type": "string", "format": "date-time"}
	}
	switch t.Kind() {
	case reflect.Pointer:
		return map[string]any{"anyOf": []any{g.schema(t.Elem()), map[string]any{"type": "null"}}}
	case reflect.String:
		return map[string]any{"type": "string"}
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return map[string]any{"type": "integer"}
	case reflect.Float32, reflect.Float64:
		return map[string]any{"type": "number"}
	case reflect.Slice, reflect.Array:
		return map[string]any{"type": []any{"array", "null"}, "items": g.schema(t.Elem())}
	case reflect.Map:
		return map[string]any{"type": []any{"object", "null"}, "additionalProperties": g.schema(t.Elem())}
	case reflect.Struct:
		name := t.Name()
		if t.PkgPath() != "" && !strings.HasSuffix(t.PkgPath(), "/model") {
			name = pkgName(t.PkgPath()) + "." + name
		}
		if _, ok := g.defs[name]; !ok {
			g.defs[name] = map[string]any{} // placeholder breaks recursion
			g.defs[name] = g.object(t)
		}
		return map[string]any{"$ref": "#/$defs/" + name}
	case reflect.Interface:
		return map[string]any{}
	}
	return map[string]any{}
}

func pkgName(p string) string { return p[strings.LastIndex(p, "/")+1:] }

func (g *gen) object(t reflect.Type) map[string]any {
	props := map[string]any{}
	var req []string
	var walk func(t reflect.Type)
	walk = func(t reflect.Type) {
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			tag := f.Tag.Get("json")
			if tag == "-" {
				continue
			}
			name, opts, _ := strings.Cut(tag, ",")
			if f.Anonymous && name == "" {
				walk(f.Type)
				continue
			}
			if name == "" {
				name = f.Name
			}
			props[name] = g.schema(f.Type)
			if !strings.Contains(opts, "omitempty") {
				req = append(req, name)
			}
		}
	}
	walk(t)
	sort.Strings(req)
	o := map[string]any{"type": "object", "properties": props}
	if len(req) > 0 {
		o["required"] = req
	}
	return o
}
