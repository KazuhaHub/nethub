package diagnostic

import (
    "io"
    "sync"
    "testing"

    frplog "github.com/fatedier/frp/pkg/util/log"
    "github.com/fatedier/frp/pkg/util/xlog"
    baselog "github.com/fatedier/golib/log"
)

func TestConcurrentRunIDPrefixAndLogRead(t *testing.T) {
    frplog.Logger = baselog.New(baselog.WithOutput(io.Discard))
    logger := xlog.New()
    logger.AddPrefix(xlog.LogPrefix{Name: "runID", Value: "first"})
    start := make(chan struct{})
    var group sync.WaitGroup
    group.Add(2)
    go func() {
        defer group.Done()
        <-start
        for i := 0; i < 10000; i++ {
            value := "first"
            if i%2 != 0 { value = "second" }
            logger.AddPrefix(xlog.LogPrefix{Name: "runID", Value: value})
        }
    }()
    go func() {
        defer group.Done()
        <-start
        for i := 0; i < 10000; i++ { logger.Infof("bounded diagnostic") }
    }()
    close(start)
    group.Wait()
}
