package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSafeFileName(t *testing.T) {
	cases := map[string]string{
		"report.pdf":                   "report.pdf",
		"../../../../Users/x/.zshrc":   "zshrc",
		"..\\..\\Windows\\evil.dll":    "evil.dll",
		"/etc/passwd":                  "passwd",
		"..":                           "file",
		".":                            "file",
		"":                             "file",
		"a\x00b\nc.txt":                "a_b_c.txt",
		"Library/LaunchAgents/x.plist": "x.plist",
		"weird:name*?.txt":             "weird_name__.txt",
	}
	for in, want := range cases {
		if got := safeFileName(in); got != want {
			t.Errorf("safeFileName(%q) = %q, want %q", in, got, want)
		}
		if strings.ContainsAny(safeFileName(in), `/\`) {
			t.Errorf("safeFileName(%q) still contains a separator", in)
		}
	}
}

func TestSafePathSegment(t *testing.T) {
	for _, in := range []string{"../../etc", "..", "a/b", `a\b`, "123@g.us/../../x"} {
		got := safePathSegment(in)
		if strings.ContainsAny(got, `/\`) || strings.HasPrefix(got, ".") || got == "" {
			t.Errorf("safePathSegment(%q) = %q is unsafe", in, got)
		}
	}
	if got := safePathSegment("123:4@s.whatsapp.net"); got != "123_4@s.whatsapp.net" {
		t.Errorf("unexpected segment %q", got)
	}
}

func TestIsWithin(t *testing.T) {
	base := filepath.Join(string(os.PathSeparator), "a", "b")
	ok := []string{base, filepath.Join(base, "c"), filepath.Join(base, "c", "d")}
	bad := []string{filepath.Join(base, ".."), filepath.Join(base, "..", "bc"), string(os.PathSeparator), filepath.Join(string(os.PathSeparator), "a", "bc")}
	for _, p := range ok {
		if !isWithin(base, p) {
			t.Errorf("isWithin(%q, %q) = false, want true", base, p)
		}
	}
	for _, p := range bad {
		if isWithin(base, p) {
			t.Errorf("isWithin(%q, %q) = true, want false", base, p)
		}
	}
}

func TestResolveOutboxPath(t *testing.T) {
	tmp := t.TempDir()
	outboxDir = filepath.Join(tmp, "outbox")
	if err := os.MkdirAll(outboxDir, 0700); err != nil {
		t.Fatal(err)
	}
	inside := filepath.Join(outboxDir, "photo.jpg")
	secret := filepath.Join(tmp, "secret.txt")
	os.WriteFile(inside, []byte("x"), 0600)
	os.WriteFile(secret, []byte("x"), 0600)
	link := filepath.Join(outboxDir, "link.txt")
	if err := os.Symlink(secret, link); err != nil {
		t.Fatal(err)
	}

	if _, err := resolveOutboxPath(inside); err != nil {
		t.Errorf("file inside outbox rejected: %v", err)
	}
	for _, p := range []string{
		secret, // outside
		filepath.Join(outboxDir, "..", "secret.txt"), // traversal
		link,                                    // symlink escaping the outbox
		outboxDir,                               // a directory, not a file
		"relative/path.jpg",                     // not absolute
		filepath.Join(outboxDir, "missing.jpg"), // missing
	} {
		if _, err := resolveOutboxPath(p); err == nil {
			t.Errorf("resolveOutboxPath(%q) accepted, want rejection", p)
		}
	}
}

func TestRecipientAllowlist(t *testing.T) {
	defer func() { allowedRecipients = nil }()

	t.Setenv("WHATSAPP_ALLOWED_RECIPIENTS", "")
	allowedRecipients = nil
	if err := loadAllowedRecipients(); err != nil {
		t.Fatal(err)
	}
	any, _ := parseRecipient("15550001111")
	if !recipientAllowed(any) {
		t.Error("with no allowlist every recipient should be allowed")
	}

	t.Setenv("WHATSAPP_ALLOWED_RECIPIENTS", "15550001111, 120363000000000000@g.us")
	if err := loadAllowedRecipients(); err != nil {
		t.Fatal(err)
	}
	for _, r := range []string{"15550001111", "15550001111@s.whatsapp.net", "120363000000000000@g.us"} {
		j, err := parseRecipient(r)
		if err != nil || !recipientAllowed(j) {
			t.Errorf("%q should be allowed (err=%v)", r, err)
		}
	}
	other, _ := parseRecipient("15559999999")
	if recipientAllowed(other) {
		t.Error("recipient outside the allowlist was allowed")
	}

	if _, err := parseRecipient("+1 555 000"); err == nil {
		t.Error("phone number with symbols should be rejected")
	}
}

func TestSecureHandler(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef0123456789abcdef"
	called := false
	h := secureHandler(token, func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	newReq := func() *http.Request {
		r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/api/send", strings.NewReader(`{}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+token)
		return r
	}

	cases := []struct {
		name   string
		mutate func(*http.Request)
		want   int
	}{
		{"valid", func(r *http.Request) {}, http.StatusOK},
		{"valid localhost host", func(r *http.Request) { r.Host = "localhost:8080" }, http.StatusOK},
		{"no token", func(r *http.Request) { r.Header.Del("Authorization") }, http.StatusUnauthorized},
		{"wrong token", func(r *http.Request) { r.Header.Set("Authorization", "Bearer nope") }, http.StatusUnauthorized},
		{"browser origin", func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") }, http.StatusForbidden},
		{"browser fetch metadata", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }, http.StatusForbidden},
		{"dns rebinding host", func(r *http.Request) { r.Host = "evil.example:8080" }, http.StatusForbidden},
		{"text/plain simple request", func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }, http.StatusUnsupportedMediaType},
		{"GET", func(r *http.Request) { r.Method = http.MethodGet }, http.StatusMethodNotAllowed},
	}
	for _, c := range cases {
		called = false
		r := newReq()
		c.mutate(r)
		w := httptest.NewRecorder()
		h(w, r)
		if w.Code != c.want {
			t.Errorf("%s: status %d, want %d", c.name, w.Code, c.want)
		}
		if called != (c.want == http.StatusOK) {
			t.Errorf("%s: handler called = %v", c.name, called)
		}
	}
}

func TestLoadOrCreateToken(t *testing.T) {
	dir := t.TempDir()
	wd, _ := os.Getwd()
	defer os.Chdir(wd)
	os.Chdir(dir)
	os.MkdirAll(storeDir, 0700)
	t.Setenv("WHATSAPP_BRIDGE_TOKEN", "")

	tok, err := loadOrCreateToken()
	if err != nil || len(tok) < 32 {
		t.Fatalf("token %q err %v", tok, err)
	}
	info, err := os.Stat(tokenFile)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("token file perms wrong: %v %v", info.Mode().Perm(), err)
	}
	again, _ := loadOrCreateToken()
	if again != tok {
		t.Error("token should be stable across restarts")
	}

	t.Setenv("WHATSAPP_BRIDGE_TOKEN", "short")
	if _, err := loadOrCreateToken(); err == nil {
		t.Error("short env token should be rejected")
	}
}

func TestAnalyzeOggOpusMalformedDoesNotPanic(t *testing.T) {
	inputs := [][]byte{
		[]byte("OggS"),
		append([]byte("OggS"), make([]byte, 23)...),
		// header claiming a 255-byte segment that isn't there
		append(append([]byte("OggS"), make([]byte, 22)...), 1, 255),
		// OpusHead right at the end of the page
		append(append(append([]byte("OggS"), make([]byte, 22)...), 1, 8), []byte("OpusHead")...),
	}
	for i, in := range inputs {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("input %d panicked: %v", i, r)
				}
			}()
			analyzeOggOpus(in)
		}()
	}
}
