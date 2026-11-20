package adapter

import "context"

// RuntimeConfig applies a revision of the CLI's original configuration file.
type RuntimeConfig interface {
	ApplyRuntimeConfig(context.Context, []byte, string) error
	RuntimeRevision() []byte
	ServiceContext(context.Context) context.Context
}
