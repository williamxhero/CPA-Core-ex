package management

import (
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/credentialassociation"
	runtimeexecutor "github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

type untrustedAssociationExecutor struct {
	coreauth.ProviderExecutor
	invoked bool
}

func (e *untrustedAssociationExecutor) CredentialAssociation(*coreauth.Auth, credentialassociation.Request) (bool, string) {
	e.invoked = true
	return true, "selected_credential_association"
}

func TestCredentialAssociationNativeSeamRejectsUnknownImplementer(t *testing.T) {
	e := &untrustedAssociationExecutor{}
	associated, reason := nativeCredentialAssociation(e, nil, credentialassociation.Request{})
	if associated || reason != "association_unsupported" || e.invoked {
		t.Fatal("structural plugin method acquired native proof authority")
	}
	for _, native := range []coreauth.ProviderExecutor{(*runtimeexecutor.CodexExecutor)(nil), (*runtimeexecutor.CodexAutoExecutor)(nil), (*runtimeexecutor.ClaudeExecutor)(nil), (*runtimeexecutor.OpenAICompatExecutor)(nil)} {
		if associated, reason := nativeCredentialAssociation(native, nil, credentialassociation.Request{}); associated || reason != "association_unsupported" {
			t.Fatal("nil native executor acquired proof authority")
		}
	}
}
