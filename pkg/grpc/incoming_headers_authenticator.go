package grpc

import (
	"context"

	"github.com/buildbarn/bb-storage/pkg/auth"
	"github.com/buildbarn/bb-storage/pkg/jmespath"
	"github.com/buildbarn/bb-storage/pkg/util"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
)

type incomingHeadersAuthenticator struct {
	metadataExtractor *jmespath.Expression
}

// NewIncomingHeadersAuthenticator creates an Authenticator that allows
// every request and derives AuthenticationMetadata from the incoming
// gRPC request metadata via the given JMESPath expression. The
// expression is evaluated against a JSON object of the shape:
//
//	{
//	  "incomingGRPCMetadata": map<string, repeated string>
//	}
//
// matching the input model already used by NewJMESPathMetadataExtractor
// for outbound add-metadata interceptors. The result is interpreted as
// buildbarn.auth.AuthenticationMetadata in JSON form.
//
// Use this authenticator when authentication has been terminated at an
// upstream proxy (e.g. bb_frontend doing JWT validation) and the
// downstream service needs to reconstitute AuthenticationMetadata from
// forwarded headers without re-running an expensive auth check.
func NewIncomingHeadersAuthenticator(metadataExtractor *jmespath.Expression) Authenticator {
	return &incomingHeadersAuthenticator{
		metadataExtractor: metadataExtractor,
	}
}

func (a *incomingHeadersAuthenticator) Authenticate(ctx context.Context) (*auth.AuthenticationMetadata, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	incomingGRPCMetadata := make(map[string]any, len(md))
	for k, rawVs := range md {
		vs := make([]any, 0, len(rawVs))
		for _, rawV := range rawVs {
			vs = append(vs, rawV)
		}
		incomingGRPCMetadata[k] = vs
	}
	metadataRaw, err := a.metadataExtractor.Search(map[string]any{
		"incomingGRPCMetadata": incomingGRPCMetadata,
	})
	if err != nil {
		return nil, util.StatusWrapWithCode(err, codes.Unauthenticated, "Cannot extract metadata from incoming gRPC headers")
	}
	return auth.NewAuthenticationMetadataFromRaw(metadataRaw)
}
