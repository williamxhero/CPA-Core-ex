package pluginhost

// SupportPluginHeaderValue reports whether this binary can load provider plugins.
// Windows loads plugins without cgo. Other platforms require a cgo build.
func SupportPluginHeaderValue() string {
	return supportPluginValue
}
