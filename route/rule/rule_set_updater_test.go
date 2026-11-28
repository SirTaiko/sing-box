package rule

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
)

func TestRuleSetUpdaterMayCloseBeforeOrDuringStart(t *testing.T) {
	for _, closeFirst := range []bool{true, false} {
		set := &RemoteRuleSet{lastUpdated: time.Now(), updateInterval: 24 * time.Hour}
		u := NewRuleSetUpdater(context.Background(), []adapter.RuleSet{set})
		if closeFirst {
			_ = u.Close()
		}
		var workers sync.WaitGroup
		for range 4 {
			workers.Go(u.Start)
			workers.Go(func() { _ = u.Close() })
		}
		workers.Wait()
		select {
		case <-u.done:
		default:
			t.Fatal("updater was still running after close")
		}
	}
}
