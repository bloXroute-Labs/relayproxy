package relayproxy

import (
	"context"
)

type Delayer interface {
	DelayGetHeader(ctx context.Context, in DelayGetHeaderParams) (DelayGetHeaderResponse, error)
}
