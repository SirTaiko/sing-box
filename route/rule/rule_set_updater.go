package rule

import (
	"context"
	"sync"
	"time"

	"github.com/sagernet/sing-box/adapter"
)

type RuleSetUpdater struct {
	ctx      context.Context
	cancel   context.CancelFunc
	ruleSets []*RemoteRuleSet
	start    sync.Once
	done     chan struct{}
}

func NewRuleSetUpdater(ctx context.Context, ruleSets []adapter.RuleSet) *RuleSetUpdater {
	var remoteRuleSets []*RemoteRuleSet
	for _, ruleSet := range ruleSets {
		remoteRuleSet, isRemote := ruleSet.(*RemoteRuleSet)
		if isRemote {
			remoteRuleSets = append(remoteRuleSets, remoteRuleSet)
		}
	}
	if len(remoteRuleSets) == 0 {
		return nil
	}
	ctx, cancel := context.WithCancel(ctx)
	return &RuleSetUpdater{
		ctx:      ctx,
		cancel:   cancel,
		ruleSets: remoteRuleSets,
		done:     make(chan struct{}),
	}
}

func (u *RuleSetUpdater) Start() {
	u.start.Do(func() { go u.loopUpdate() })
}

func (u *RuleSetUpdater) Close() error {
	u.cancel()
	// Also finish a resource discarded before its Started stage.
	u.start.Do(func() { close(u.done) })
	<-u.done
	return nil
}

func (u *RuleSetUpdater) loopUpdate() {
	defer close(u.done)
	nextUpdates := make([]time.Time, len(u.ruleSets))
	for i, ruleSet := range u.ruleSets {
		nextUpdates[i] = ruleSet.lastUpdated.Add(ruleSet.updateInterval)
	}
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-u.ctx.Done():
			return
		case <-timer.C:
		}
		now := time.Now()
		for i, ruleSet := range u.ruleSets {
			if u.ctx.Err() != nil {
				return
			}
			if now.Before(nextUpdates[i]) {
				continue
			}
			ruleSet.updateOnce(u.ctx)
			nextUpdates[i] = now.Add(ruleSet.updateInterval)
		}
		timer.Reset(waitUntilNext(nextUpdates))
	}
}

func waitUntilNext(nextUpdates []time.Time) time.Duration {
	next := nextUpdates[0]
	for _, nextUpdate := range nextUpdates[1:] {
		if nextUpdate.Before(next) {
			next = nextUpdate
		}
	}
	wait := time.Until(next)
	if wait < 0 {
		return 0
	}
	return wait
}
