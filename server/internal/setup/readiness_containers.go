package setup

import "errors"

var ErrContainerReadiness = errors.New("runtime container separation could not be verified")
