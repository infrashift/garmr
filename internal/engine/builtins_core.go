package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

func builtinLen(ctx context.Context, args ...any) (any, error) {
	if len(args) != 1 {
		return nil, errors.New("len requires exactly 1 argument")
	}
	switch v := args[0].(type) {
	case string:
		return utf8.RuneCountInString(v), nil
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

// builtinMatches reports whether a string matches a regular expression:
// matches(s, pattern). Patterns go through the bounded shared cache, since
// they may come from the input.
func builtinMatches(ctx context.Context, args ...any) (any, error) {
	if len(args) != 2 {
		return nil, errors.New("matches requires exactly 2 arguments")
	}
	s, ok1 := args[0].(string)
	pattern, ok2 := args[1].(string)
	if !ok1 || !ok2 {
		return nil, errors.New("matches: arguments must be strings")
	}
	re, err := sharedRegexCache.get(pattern)
	if err != nil {
		return nil, fmt.Errorf("matches: invalid pattern: %w", err)
	}
	return re.MatchString(s), nil
}

func builtinNow(ctx context.Context, args ...any) (any, error) {
	return time.Now().UTC().Format(time.RFC3339), nil
}
