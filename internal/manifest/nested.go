package manifest

// The helpers below walk a chain of nested map[string]any keys -- the
// shape every rule needs to reach into, since a decoded YAML document is
// just maps and slices, not a fixed Go struct per Kind.

// NestedMap returns the map at path, or (nil, false) if any step along
// the way is missing or not itself a map.
func NestedMap(m map[string]any, path ...string) (map[string]any, bool) {
	cur := m
	for _, key := range path {
		if cur == nil {
			return nil, false
		}
		next, ok := cur[key].(map[string]any)
		if !ok {
			return nil, false
		}
		cur = next
	}
	return cur, true
}

// NestedBool returns the bool at path, or (false, false) if it is
// missing or not a bool.
func NestedBool(m map[string]any, path ...string) (bool, bool) {
	if len(path) == 0 {
		return false, false
	}
	parent, ok := NestedMap(m, path[:len(path)-1]...)
	if !ok {
		return false, false
	}
	v, ok := parent[path[len(path)-1]].(bool)
	return v, ok
}

// NestedString returns the string at path, or ("", false) if it is
// missing or not a string.
func NestedString(m map[string]any, path ...string) (string, bool) {
	if len(path) == 0 {
		return "", false
	}
	parent, ok := NestedMap(m, path[:len(path)-1]...)
	if !ok {
		return "", false
	}
	v, ok := parent[path[len(path)-1]].(string)
	return v, ok
}

// NestedSlice returns the slice at path, or (nil, false) if it is
// missing or not a slice.
func NestedSlice(m map[string]any, path ...string) ([]any, bool) {
	if len(path) == 0 {
		return nil, false
	}
	parent, ok := NestedMap(m, path[:len(path)-1]...)
	if !ok {
		return nil, false
	}
	v, ok := parent[path[len(path)-1]].([]any)
	return v, ok
}

// StringSlice converts a []any of strings (as YAML always decodes a
// string list) into a []string, skipping any element that isn't one.
func StringSlice(items []any) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
