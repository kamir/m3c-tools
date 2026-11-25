package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// plaudSyncTestEnv points the ER1 config at srv with a synthetic key, a
// throwaway HOME and no Keychain, so nothing on the test machine leaks in.
func plaudSyncTestEnv(t *testing.T, srv *httptest.Server) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("M3C_ER1_KEYCHAIN", "off")
	t.Setenv("M3C_TOKEN_STORE", "file")
	t.Setenv("ER1_DEVICE_TOKEN", "")
	t.Setenv("ER1_API_URL", srv.URL+"/upload_2")
	t.Setenv("ER1_API_KEY", "test-key-not-a-credential")
	t.Setenv("ER1_CONTEXT_ID", "test___mft")
}

// plaudSyncTestServer answers the sync check with checkStatus and counts
// every other request, which would be an upload or a mapping write.
func plaudSyncTestServer(t *testing.T, checkStatus int, checkBody string, others *atomic.Int32) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/api/plaud-sync/check") {
			w.WriteHeader(checkStatus)
			_, _ = w.Write([]byte(checkBody))
			return
		}
		others.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// BUG-0617: a failed server check used to fall back to the local ledger
// without a word. On that basis every recording synced from another machine
// looked new, and a sync of all recordings uploaded them again.
func TestPlaudSyncStatesReportAFailedServerCheck(t *testing.T) {
	var others atomic.Int32
	srv := plaudSyncTestServer(t, http.StatusInternalServerError, "boom", &others)
	plaudSyncTestEnv(t, srv)

	states, err := resolvePlaudSyncStates([]string{"of_aaaa1111bbbb2222cccc3333dddd4444"}, "plaud-test-token")

	if err == nil {
		t.Fatal("a failed server check must be reported, not replaced by the local ledger")
	}
	if len(states) != 0 {
		t.Fatalf("local ledger of a fresh HOME must be empty, got %v", states)
	}
}

func TestPlaudSyncStatesReportAMissingCredential(t *testing.T) {
	var others atomic.Int32
	srv := plaudSyncTestServer(t, http.StatusOK, `{"synced":{},"unsynced":[]}`, &others)
	plaudSyncTestEnv(t, srv)

	if _, err := resolvePlaudSyncStates([]string{"of_x"}, ""); err == nil {
		t.Fatal("without a Plaud token the server check cannot run; that must be reported")
	}
}

func TestPlaudSyncStatesTakeTheServerAnswer(t *testing.T) {
	var others atomic.Int32
	body := `{"synced":{"of_aaaa1111bbbb2222cccc3333dddd4444":{"er1_doc_id":"DOC1"}},"unsynced":["of_new"]}`
	srv := plaudSyncTestServer(t, http.StatusOK, body, &others)
	plaudSyncTestEnv(t, srv)

	states, err := resolvePlaudSyncStates([]string{"of_aaaa1111bbbb2222cccc3333dddd4444", "of_new"}, "plaud-test-token")

	if err != nil {
		t.Fatalf("server check succeeded, got error %v", err)
	}
	if st := states["of_aaaa1111bbbb2222cccc3333dddd4444"]; !plaudStateSynced(st) || st.DocID != "DOC1" {
		t.Fatalf("synced recording not taken from the server answer: %+v", st)
	}
	if plaudStateSynced(states["of_new"]) {
		t.Fatal("an unsynced recording must not look synced")
	}
}
