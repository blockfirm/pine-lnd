package pine

import context "context"

// Implements the PerRPCCredentials interface.
type pineCredentials struct {
	id string
}

// GetRequestMetadata gets the current request metadata.
func (c pineCredentials) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	metadata := make(map[string]string)
	metadata["pine-id"] = c.id

	return metadata, nil
}

// RequireTransportSecurity indicates whether the credentials requires transport security.
func (c pineCredentials) RequireTransportSecurity() bool {
	return false
}
