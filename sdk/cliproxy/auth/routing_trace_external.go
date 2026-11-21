package auth

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/clienterror"
	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

func recordHomeRoutingStage(ctx context.Context, a *Auth, reason string) {
	trace := routingTraceFromContext(ctx)
	if trace == nil {
		return
	}
	stage := SchedulingDecision{Mode: trace.data.Mode, Source: "home", Coverage: "partial", Reason: reason}
	if a != nil {
		id, _ := schedulingResource(a)
		row := SchedulingCandidateDecision{
			ResourceID: id, Family: schedulingDiagnosticFamily(a), Registered: true,
			Recheck: schedulingKnownTime(time.Time{}),
		}
		last, _ := authLastRefreshTimestamp(a)
		if a.LastRefreshedAt.After(last) {
			last = a.LastRefreshedAt
		}
		row.Refresh = schedulingKnownTime(last)
		stage.Counts.Inventory, stage.Counts.Registered = 1, 1
		switch reason {
		case "":
			row.Eligible, row.Available = true, true
			stage.Counts.Eligible, stage.Counts.Available, stage.Counts.Selected = 1, 1, 1
			stage.SelectedResourceID, stage.ActualResourceID = id, id
		default:
			row.Reasons = []string{reason}
			stage.Counts.Excluded = 1
		}
		stage.Candidates = []SchedulingCandidateDecision{row}
	}
	recordRoutingStage(ctx, stage)
}

func recordHomeRoutingPickFailure(ctx context.Context, err error) {
	reason := "home_dispatch_failed"
	switch {
	case errors.Is(err, context.Canceled):
		reason = "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		reason = "deadline_exceeded"
	case isCredentialSelectionFailure(err):
		reason = "home_no_dispatch"
	}
	recordHomeRoutingStage(ctx, nil, reason)
}

// RecordExternalExecutorRouting records a decision at the host boundary.
// An executor can do local work, call Core, or use its own network transport.
func RecordExternalExecutorRouting(ctx context.Context, reason string) {
	switch reason {
	case "", "hard_binding", "funding_ineligible", "executor_not_available", "home_enabled":
	default:
		reason = "executor_not_available"
	}
	trace := routingTraceFromContext(ctx)
	if trace == nil {
		return
	}
	stage := SchedulingDecision{Mode: trace.data.Mode, Source: "plugin", Coverage: "partial", Reason: reason}
	if reason == "" {
		stage.Counts.Selected = 1
		stage.TransportVisibility = "unknown"
	} else {
		stage.Counts.Excluded = 1
	}
	recordRoutingStage(ctx, stage)
}

// ExternalExecutorDisabledByHome reports the existing mutually exclusive route rule.
func ExternalExecutorDisabledByHome(ctx context.Context, model string) error {
	RecordExternalExecutorRouting(ctx, "home_enabled")
	if trace := routingTraceFromContext(ctx); trace != nil && trace.data.Mode == internalconfig.ProviderSchedulingEnforce {
		return newNoAvailableRouteError(model)
	}
	return &Error{HTTPStatus: http.StatusServiceUnavailable, Message: "plugin executor routing is unavailable while Home is enabled"}
}

// ExternalExecutorRoutingError redacts opaque plugin failures without asserting
// that the plugin reached a provider or that any retry hint is trustworthy.
func ExternalExecutorRoutingError(ctx context.Context, err error) error {
	err = RoutingErrorForResponse(ctx, err)
	trace := routingTraceFromContext(ctx)
	var safe *RoutingFailure
	if trace == nil || trace.data.Mode != internalconfig.ProviderSchedulingEnforce || err == nil || errors.As(err, &safe) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	status := clienterror.HTTPStatusFromErrorOr(err, http.StatusInternalServerError)
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		status = http.StatusBadGateway
	case status == http.StatusTooManyRequests || status >= 500 && status <= 599:
	default:
		return err
	}
	return &RoutingFailure{
		Code: "external_executor_failed", Type: "server_error", Message: "The external executor could not complete the request.",
		Model: trace.data.Model, RequestID: trace.data.RequestID, status: status,
	}
}
