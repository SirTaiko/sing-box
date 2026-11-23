package route

import (
	"context"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"
)

// A live rule set owns its file watcher or downloader across routing revisions.
type liveRuleSet struct {
	ctx     context.Context
	set     adapter.RuleSet
	users   atomic.Int32
	updater *R.RuleSetUpdater
}

func (s *liveRuleSet) release() error {
	if s.users.Add(-1) != 0 {
		return nil
	}
	if s.updater != nil {
		_ = s.updater.Close()
	}
	return s.set.Close()
}

func (r *Router) ReusableRuleSet(tag string) bool {
	old := r.liveSets[tag]
	if old == nil {
		return false
	}
	source, ok := old.set.(interface{ HasLoadedRules() bool })
	return ok && source.HasLoadedRules()
}

func (r *Router) InitializeLive(resourceCtx context.Context, rules []option.Rule, sets []option.RuleSet, scope *adapter.Scope, previous *Router, canReuse func(string) bool) error {
	r.liveSets = make(map[string]*liveRuleSet)
	r.liveSetsBound = scope != nil
	bind := func(tag string, asset *liveRuleSet) adapter.RuleSet {
		r.liveSets[tag] = asset
		if scope != nil {
			asset.users.Add(1)
			scope.Add(asset.release)
		}
		return asset.set
	}
	return r.initialize(rules, sets, func(tag string, options option.RuleSet) (adapter.RuleSet, error) {
		if previous != nil && canReuse(tag) && previous.ReusableRuleSet(tag) {
			old := previous.liveSets[tag]
			return bind(tag, old), nil
		}
		set, err := R.NewRuleSet(resourceCtx, r.logger, tag, options)
		if err != nil {
			return nil, err
		}
		r.newSets = append(r.newSets, set)
		return bind(tag, &liveRuleSet{ctx: resourceCtx, set: set}), nil
	})
}

func (r *Router) prepareRuleSetUpdaters(ctx context.Context, scope *adapter.Scope) {
	if r.liveSets == nil {
		r.ruleSetUpdater = R.NewRuleSetUpdater(ctx, r.ruleSets)
		if r.ruleSetUpdater != nil {
			scope.Add(r.ruleSetUpdater.Close)
		}
		return
	}
	for _, set := range r.newSets {
		asset := r.liveSets[set.Name()]
		asset.updater = R.NewRuleSetUpdater(asset.ctx, []adapter.RuleSet{set})
	}
}

func (r *Router) startRuleSetUpdaters() {
	if r.ruleSetUpdater != nil {
		r.ruleSetUpdater.Start()
	}
	for _, set := range r.newSets {
		if u := r.liveSets[set.Name()].updater; u != nil {
			u.Start()
		}
	}
}
