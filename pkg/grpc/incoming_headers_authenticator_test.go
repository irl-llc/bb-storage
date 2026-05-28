package grpc_test

import (
	"context"
	"testing"

	"github.com/buildbarn/bb-storage/pkg/grpc"
	"github.com/buildbarn/bb-storage/pkg/jmespath"
	"github.com/stretchr/testify/require"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// TestIncomingHeadersAuthenticator exercises the allow-all-with-dynamic-
// metadata authenticator that derives AuthenticationMetadata from
// incoming gRPC headers via JMESPath. Symmetric counterpart to
// NewJMESPathMetadataExtractor for outbound interceptors.
func TestIncomingHeadersAuthenticator(t *testing.T) {
	ctx := context.Background()

	// Extracts {private: {access_token: <first value of x-google-access-token>}}.
	// Mirrors the canonical use case: an upstream proxy forwards a
	// short-lived OAuth access token via gRPC header, and this service
	// stashes it in AuthenticationMetadata.private so that outbound
	// gRPC interceptors (via add_metadata_jmespath_expression) can
	// surface it on calls to downstream services.
	authenticator := grpc.NewIncomingHeadersAuthenticator(
		jmespath.MustCompile(`{"private": {"access_token": incomingGRPCMetadata."x-google-access-token" | [0]}}`),
	)

	t.Run("NoIncomingMetadata", func(t *testing.T) {
		// No incoming gRPC metadata at all — JMESPath sees an empty
		// map, the expression evaluates with a null access_token, and
		// the resulting AuthenticationMetadata is well-formed but
		// empty.
		md, err := authenticator.Authenticate(ctx)
		require.NoError(t, err)
		require.NotNil(t, md)
	})

	t.Run("HeaderPresent", func(t *testing.T) {
		ctxWithHeader := metadata.NewIncomingContext(
			ctx,
			metadata.Pairs("x-google-access-token", "ya29.example-token"),
		)
		md, err := authenticator.Authenticate(ctxWithHeader)
		require.NoError(t, err)
		require.Equal(t, map[string]any{
			"private": map[string]any{
				"access_token": "ya29.example-token",
			},
		}, md.GetRaw())
		// The private field is what the AuthenticationMetadata API
		// surfaces only via GetFullProto / GetRaw — never via the
		// public-display path.
		require.NotNil(t, md.GetFullProto().GetPrivate())
		require.Nil(t, md.GetFullProto().GetPublic())
	})

	t.Run("MultipleHeaderValuesFirstWins", func(t *testing.T) {
		// gRPC permits repeated header values for the same key; the
		// expression's `| [0]` indexer picks the first deterministically.
		ctxWithHeader := metadata.NewIncomingContext(
			ctx,
			metadata.Pairs(
				"x-google-access-token", "first",
				"x-google-access-token", "second",
			),
		)
		md, err := authenticator.Authenticate(ctxWithHeader)
		require.NoError(t, err)
		require.Equal(t, "first", md.GetRaw()["private"].(map[string]any)["access_token"])
	})

	t.Run("UnrelatedHeadersIgnored", func(t *testing.T) {
		ctxWithUnrelated := metadata.NewIncomingContext(
			ctx,
			metadata.Pairs("user-agent", "grpc-go/1.x"),
		)
		md, err := authenticator.Authenticate(ctxWithUnrelated)
		require.NoError(t, err)
		require.NotNil(t, md)
	})

	t.Run("EmptyExpression", func(t *testing.T) {
		// The proto comment advertises `{}` as the way to extract no
		// metadata. Verify this round-trips to an empty
		// AuthenticationMetadata.
		emptyAuthenticator := grpc.NewIncomingHeadersAuthenticator(
			jmespath.MustCompile("`{}`"),
		)
		md, err := emptyAuthenticator.Authenticate(ctx)
		require.NoError(t, err)
		require.NotNil(t, md)
		require.Empty(t, md.GetRaw())
	})

	t.Run("ExpressionInvalidShape", func(t *testing.T) {
		// If the JMESPath evaluates to something that isn't a valid
		// AuthenticationMetadata shape (e.g., a bare scalar), the
		// authenticator surfaces the deserialization error as
		// Unauthenticated.
		bogusAuthenticator := grpc.NewIncomingHeadersAuthenticator(
			jmespath.MustCompile("`42`"),
		)
		_, err := bogusAuthenticator.Authenticate(ctx)
		require.Error(t, err)
		// Either codes.Unauthenticated (Cannot extract …) or
		// codes.InvalidArgument from NewAuthenticationMetadataFromRaw
		// is acceptable — both are the "your config is wrong" signal.
		code := status.Code(err)
		if code != codes.Unauthenticated && code != codes.InvalidArgument {
			t.Fatalf("unexpected gRPC code: %v (err: %v)", code, err)
		}
	})
}
