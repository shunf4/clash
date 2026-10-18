package adapter

import "context"

// mod: delay test logging support
//
// A delay test started on purpose (dashboard / REST API) is worth two log lines
// (start and finish), while the periodic proxy provider health check runs every
// few hundred seconds for every node and must stay quiet. The two paths share
// the exact same URLTest implementation, so the caller marks its context here
// and URLTest only emits the verbose logs when the marker is present.
type delayTestLogKey struct{}

// WithDelayTestLog marks ctx as belonging to an explicit delay test request.
func WithDelayTestLog(ctx context.Context) context.Context {
	return context.WithValue(ctx, delayTestLogKey{}, true)
}

func delayTestLogEnabled(ctx context.Context) bool {
	enabled, _ := ctx.Value(delayTestLogKey{}).(bool)
	return enabled
}
