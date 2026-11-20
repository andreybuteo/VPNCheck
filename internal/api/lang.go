package api

import (
	"net/http"

	"vpncheck/internal/i18n"
	"vpncheck/internal/server"
)

// LangHeader carries the interface language with every API request. VPN Check
// serves one local user, so the language is a process-wide setting that the
// texts generated afterwards (verdicts, errors, exports) are written in.
const LangHeader = "X-VPNCheck-Lang"

// apiRouter registers handlers that first apply the request's language.
type apiRouter struct{ s *server.Server }

func (r apiRouter) HandleAPI(pattern string, h http.HandlerFunc) {
	r.s.HandleAPI(pattern, func(w http.ResponseWriter, req *http.Request) {
		if l := i18n.Normalize(req.Header.Get(LangHeader)); l != "" {
			i18n.Set(l)
		}
		h(w, req)
	})
}

// handleCatalog returns the translation catalog of one language (source text ->
// translation) and the list of languages.
func (a *API) handleCatalog(w http.ResponseWriter, r *http.Request) {
	lang := i18n.Normalize(r.PathValue("lang"))
	if lang == "" {
		writeErr(w, http.StatusNotFound, "not_found", "Язык не найден.", nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"lang": lang, "languages": i18n.Languages, "catalog": i18n.Catalog(lang)})
}
