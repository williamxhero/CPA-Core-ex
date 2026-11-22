package resourcecatalog

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/resource"
)

const pluginQuotaOwner = "core.subscription-quota.v1"

func pluginQuotaSource(protocol string) bool {
	return protocol == "opencode-go-usage" || protocol == "qwen-coding-plan-cli"
}
func pluginQuotaEvidence(id string) (*resource.QuotaGateEvidence, int64) {
	p := strings.Split(id, "/")
	if len(p) != 5 || p[0] != "subscription-quota" {
		return nil, 0
	}
	observed, e1 := strconv.ParseInt(p[2], 10, 64)
	reset, e2 := strconv.ParseInt(p[3], 10, 64)
	intake, e3 := strconv.ParseInt(p[4], 10, 64)
	if e1 != nil || e2 != nil || e3 != nil || observed <= 0 || intake <= 0 {
		return nil, 0
	}
	return &resource.QuotaGateEvidence{Window: p[1], ObservedAtMS: observed, RecheckAtMS: reset}, intake
}

// Only typed credential-wide upstream rejections reach this entry point.
func (c *Catalog) PluginQuotaRejected(src resource.QuotaSource, now time.Time) error {
	if src.State != "ready" || !pluginQuotaSource(src.Protocol) {
		return nil
	}
	return c.setPluginQuota(src.Binding, src.AuthIndex, src.SourceVersion, now, now.UnixMilli(), "upstream", 0, true, false, false)
}
func (c *Catalog) RecheckPluginQuota(index string, start time.Time, o resource.QuotaObservation) error {
	if !pluginQuotaSource(o.Protocol) || o.ProtocolVersion != 1 || o.QueryStatus != "success" {
		return nil
	}
	age := 5 * time.Minute
	if o.Protocol == "qwen-coding-plan-cli" {
		if o.AccountProvenance != "configured_cli_profile" || o.TimestampProvenance != "local_cli_acquisition_time" {
			return nil
		}
		if len(o.Windows) == 1 && o.Windows[0].Name == "monthly" {
			age = 45 * time.Minute
		}
	} else if o.AccountProvenance != "selected_key_subscription" || o.TimestampProvenance != "upstream_http_date" {
		return nil
	}
	now := time.Now()
	if o.ObservedAtMS < now.Add(-age).UnixMilli() || o.ObservedAtMS > now.Add(time.Minute).UnixMilli() {
		return nil
	}
	seen := map[string]bool{}
	limited := ""
	var due int64
	positive := true
	for _, w := range o.Windows {
		if (w.Name != "rolling" && w.Name != "weekly" && w.Name != "monthly") || seen[w.Name] || w.Model != "" {
			return nil
		}
		seen[w.Name] = true
		reset, err := time.Parse(time.RFC3339Nano, w.ResetAt)
		if err != nil || !reset.After(now) {
			positive = false
			continue
		}
		if w.SourceStatus == "rate-limited" && w.RemainingFraction == 0 {
			if limited == "" || reset.UnixMilli() < due {
				limited = w.Name
				due = reset.UnixMilli()
			}
		} else if (w.SourceStatus != "allowed" && w.SourceStatus != "ok") || !(w.RemainingFraction > 0) {
			positive = false
		}
	}
	complete := o.Complete && seen["weekly"] && seen["monthly"] && seen["rolling"]
	monthOnly := !o.Complete && o.Protocol == "qwen-coding-plan-cli" && len(seen) == 1 && seen["monthly"]
	if !complete && !monthOnly {
		return nil
	}
	if limited != "" {
		return c.setPluginQuota(o.Binding, index, o.SourceVersion, start, o.ObservedAtMS, limited, due, true, monthOnly, true)
	}
	if !positive {
		return nil
	}
	return c.setPluginQuota(o.Binding, index, o.SourceVersion, start, o.ObservedAtMS, "available", 0, false, monthOnly, true)
}
func (c *Catalog) setPluginQuota(b resource.Binding, index, source string, start time.Time, observed int64, window string, reset int64, pause, monthlyOnly, fromQuery bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.currentLocked() || !c.gateCurrentLocked() {
		return ErrUnavailable
	}
	if len(b.Targets) == 0 || !c.bindingLocked(&b) || !validSeal(source) {
		return ErrConflict
	}
	slot := "subscription-state/" + b.Targets[0].ResourceID
	old := c.state.Gates.Operations[slot].Operation
	if prior, intake := pluginQuotaEvidence(old.EvidenceID); prior != nil && old.SourceVersion == source && sameGateSubjects(old.Targets, b.Targets) {
		if observed < prior.ObservedAtMS || fromQuery && (observed == prior.ObservedAtMS || start.UnixNano() <= intake) {
			return nil
		}
	}
	active := false
	oldWindow := ""
	for _, g := range c.state.Gates.Gates {
		if g.Owner == pluginQuotaOwner && sameGateSubjects(g.Targets, b.Targets) {
			active = true
			if facts, _ := pluginQuotaEvidence(g.EvidenceID); facts != nil {
				oldWindow = facts.Window
			}
			break
		}
	}
	if monthlyOnly && active && oldWindow != "monthly-only" {
		return nil
	}
	if monthlyOnly && pause {
		window = "monthly-only"
	}
	action := "clear"
	if pause {
		action = "pause"
	}
	op := resource.GateOperation{Version: 1, OpID: uuid.NewString(), ExpectedRevision: c.state.Gates.Revision, Binding: b, AuthIndex: index, SourceVersion: source, Subject: "credential", Owner: pluginQuotaOwner, Reason: "quota_windows_exhausted", Action: action, EvidenceID: fmt.Sprintf("subscription-quota/%s/%d/%d/%d", window, observed, reset, time.Now().UnixNano())}
	change := active != pause
	if active && pause && fromQuery {
		for _, g := range c.state.Gates.Gates {
			if g.Owner == pluginQuotaOwner && sameGateSubjects(g.Targets, b.Targets) {
				facts, _ := pluginQuotaEvidence(g.EvidenceID)
				change = facts == nil || facts.Window != window || facts.RecheckAtMS != reset
				break
			}
		}
	}
	_, err := c.applyGateWithPrivateFenceLocked(op, slot, change, "")
	return err
}
