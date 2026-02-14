package engine

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

func builtinLen(ctx context.Context, args ...any) (any, error) {
	if len(args) != 1 {
		return nil, errors.New("len requires exactly 1 argument")
	}
	switch v := args[0].(type) {
	case string:
		return len(v), nil
	case []any:
		return len(v), nil
	case map[string]any:
		return len(v), nil
	default:
		return nil, fmt.Errorf("len: unsupported type %T", args[0])
	}
}

func builtinLower(ctx context.Context, args ...any) (any, error) {
	if len(args) != 1 {
		return nil, errors.New("lower requires exactly 1 argument")
	}
	if s, ok := args[0].(string); ok {
		return strings.ToLower(s), nil
	}
	return nil, errors.New("lower: argument must be string")
}

func builtinUpper(ctx context.Context, args ...any) (any, error) {
	if len(args) != 1 {
		return nil, errors.New("upper requires exactly 1 argument")
	}
	if s, ok := args[0].(string); ok {
		return strings.ToUpper(s), nil
	}
	return nil, errors.New("upper: argument must be string")
}

func builtinContains(ctx context.Context, args ...any) (any, error) {
	if len(args) != 2 {
		return nil, errors.New("contains requires exactly 2 arguments")
	}
	s, ok1 := args[0].(string)
	substr, ok2 := args[1].(string)
	if ok1 && ok2 {
		return strings.Contains(s, substr), nil
	}
	return nil, errors.New("contains: arguments must be strings")
}

func builtinStartsWith(ctx context.Context, args ...any) (any, error) {
	if len(args) != 2 {
		return nil, errors.New("startsWith requires exactly 2 arguments")
	}
	s, ok1 := args[0].(string)
	prefix, ok2 := args[1].(string)
	if ok1 && ok2 {
		return strings.HasPrefix(s, prefix), nil
	}
	return nil, errors.New("startsWith: arguments must be strings")
}

func builtinEndsWith(ctx context.Context, args ...any) (any, error) {
	if len(args) != 2 {
		return nil, errors.New("endsWith requires exactly 2 arguments")
	}
	s, ok1 := args[0].(string)
	suffix, ok2 := args[1].(string)
	if ok1 && ok2 {
		return strings.HasSuffix(s, suffix), nil
	}
	return nil, errors.New("endsWith: arguments must be strings")
}

func builtinMatches(ctx context.Context, args ...any) (any, error) {
	if len(args) != 2 {
		return nil, errors.New("matches requires exactly 2 arguments")
	}
	s, ok1 := args[0].(string)
	pattern, ok2 := args[1].(string)
	if ok1 && ok2 {
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("matches: invalid pattern: %w", err)
		}
		return re.MatchString(s), nil
	}
	return nil, errors.New("matches: arguments must be strings")
}

func builtinNow(ctx context.Context, args ...any) (any, error) {
	return time.Now().UTC().Format(time.RFC3339), nil
}
