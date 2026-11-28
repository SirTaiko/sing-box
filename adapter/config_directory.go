package adapter

import "context"

type configDirectoryKey struct{}

// ContextWithConfigDirectory records the directory of the loaded sing-box
// configuration so outbound features with relative file options can resolve
// them against the configuration instead of the process working directory.
func ContextWithConfigDirectory(ctx context.Context, directory string) context.Context {
	if directory == "" {
		return ctx
	}
	return context.WithValue(ctx, configDirectoryKey{}, directory)
}

// ConfigDirectoryFromContext returns the configuration directory recorded by
// ContextWithConfigDirectory, or an empty string for programmatic users.
func ConfigDirectoryFromContext(ctx context.Context) string {
	directory, _ := ctx.Value(configDirectoryKey{}).(string)
	return directory
}
