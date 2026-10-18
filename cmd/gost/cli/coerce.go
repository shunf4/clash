package cli

import (
	"strconv"
	"strings"
)

// Coerce converts a query string into the type the configuration decoders
// expect: booleans stay booleans, integers stay integers, comma separated
// values become lists and "[a,b]" becomes a list too.
func Coerce(value string) any {
	switch strings.ToLower(value) {
	case "true":
		return true
	case "false":
		return false
	}
	if i, err := strconv.ParseInt(value, 10, 64); err == nil {
		return i
	}
	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		inner := strings.TrimSpace(value[1 : len(value)-1])
		if inner == "" {
			return []string{}
		}
		return splitList(inner)
	}
	if strings.Contains(value, ",") {
		return splitList(value)
	}
	return value
}

func splitList(value string) []string {
	parts := strings.Split(value, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}
