package auth

// ExecutorForAuth resolves the executor using the same credential selector as
// inference dispatch. Provider alone need not identify the selected executor.
// This lookup performs no credential preparation, inference or network I/O.
func (m *Manager) ExecutorForAuth(auth *Auth) (ProviderExecutor, bool) {
	if auth == nil {
		return nil, false
	}
	return m.Executor(executorKeyFromAuth(auth))
}
