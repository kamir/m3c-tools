package registry

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	nativeGitMetadataMax  = 1 << 20
	nativeGitArchiveMax   = 16 << 20
	nativeGitBlobJSONMax  = 24 << 20
	nativeGitResponsesMax = 64 << 20
	nativeGitEntriesMax   = 4096
	nativeGitObjectsMax   = 2048
)

type nativeGitFetch struct {
	ctx                                                                           context.Context
	source                                                                        *NativeGitSource
	journal                                                                       *NativeJournal
	secret                                                                        string
	transport                                                                     *http.Transport
	work                                                                          nativeLiveWork
	requests, objects, entries, treeEntries, pathBytes, eventBytes, responseBytes int
	seenObjects                                                                   map[string]bool
	trees                                                                         map[string][]nativeGitEntry
	verifiedPaths                                                                 map[string]string
	blobs                                                                         map[string][]byte
	records                                                                       []nativeGitRecord
}

func newNativeGitFetch(ctx context.Context, s *NativeGitSource, j *NativeJournal, secret string) *nativeGitFetch {
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	config := &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
	if s.roots != nil {
		config.RootCAs = s.roots.Clone()
	}
	dial := s.dialContext
	if dial == nil {
		dial = (&net.Dialer{Timeout: 5 * time.Second}).DialContext
	}
	transport := &http.Transport{DialContext: dial, TLSClientConfig: config, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second, MaxResponseHeaderBytes: 16 << 10, DisableKeepAlives: true, DisableCompression: true, Protocols: protocols, TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}}
	return &nativeGitFetch{ctx: ctx, source: s, journal: j, secret: secret, transport: transport, seenObjects: map[string]bool{}, trees: map[string][]nativeGitEntry{}, verifiedPaths: map[string]string{}, blobs: map[string][]byte{}}
}
func (f *nativeGitFetch) apiPath(suffix string) string {
	if f.source.provider == "github" {
		return f.source.base + "/repos/" + f.source.repository + suffix
	}
	return f.source.base + "/projects/" + url.PathEscape(f.source.repository) + "/repository" + suffix
}
func (f *nativeGitFetch) get(endpoint string, limit int, jsonBody bool) (raw []byte, header http.Header, resultErr error) {
	if limit < 1 || limit > nativeGitBlobJSONMax || f.requests >= 2048 {
		return nil, nil, ErrNativeEvidenceInvalid
	}
	if err := f.ctx.Err(); err != nil {
		return nil, nil, nativeGitIO(err)
	}
	// All endpoints are assembled from immutable validated metadata, fixed route
	// literals, OIDs and escaped query values; returned URLs are never followed.
	req, err := http.NewRequestWithContext(f.ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, nil, nativeGitIO(err)
	}
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Accept", "application/json")
	if !jsonBody {
		req.Header.Set("Accept", "application/octet-stream")
	}
	if f.source.authMode == "external-env" {
		if f.source.provider == "github" {
			req.Header.Set("Authorization", "Bearer "+f.secret)
		} else {
			req.Header.Set("PRIVATE-TOKEN", f.secret)
		}
	}
	f.requests++
	resp, err := f.transport.RoundTrip(req)
	if err != nil {
		return nil, nil, nativeGitIO(err)
	}
	defer func() {
		closeBody := f.source.closeBody
		if closeBody == nil {
			closeBody = func(body io.ReadCloser) error { return body.Close() }
		}
		if e := errors.Join(closeBody(resp.Body), f.ctx.Err()); e != nil {
			resultErr = errors.Join(resultErr, nativeGitIO(e))
		}
		if resultErr != nil {
			raw = nil
			header = nil
		}
	}()
	if resp.StatusCode != http.StatusOK {
		return nil, nil, nativeGitIO(ErrNativeGitSourceIO)
	}
	media, params, e := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	encoding := resp.Header.Get("Content-Encoding")
	allowed := media == "application/json" || media == "application/vnd.github+json"
	if !jsonBody {
		allowed = allowed || media == "application/octet-stream" || media == "text/plain"
	}
	if e != nil || !allowed || len(resp.Header.Values("Content-Type")) != 1 || len(params) > 1 || (len(params) == 1 && !strings.EqualFold(params["charset"], "utf-8")) || len(resp.Header.Values("Content-Encoding")) > 1 || (encoding != "" && !strings.EqualFold(encoding, "identity")) || resp.Header.Get("Content-Range") != "" || resp.ContentLength > int64(limit) {
		return nil, nil, ErrNativeEvidenceInvalid
	}
	if e = f.work.charge(32 << 10); e != nil {
		return nil, nil, e
	}
	chunk := make([]byte, 32<<10)
	for {
		if e = f.ctx.Err(); e != nil {
			return nil, nil, nativeGitIO(e)
		}
		n, readErr := resp.Body.Read(chunk)
		if n > 0 {
			if n > limit-len(raw) || n > nativeGitResponsesMax-f.responseBytes {
				return nil, nil, ErrNativeEvidenceInvalid
			}
			if e = f.work.charge(4 * int64(n)); e != nil {
				return nil, nil, e
			}
			raw = append(raw, chunk[:n]...)
			f.responseBytes += n
		}
		if readErr != nil {
			if readErr != io.EOF {
				return nil, nil, nativeGitIO(readErr)
			}
			break
		}
	}
	if resp.ContentLength >= 0 && int64(len(raw)) != resp.ContentLength {
		return nil, nil, nativeGitIO(io.ErrUnexpectedEOF)
	}
	return raw, resp.Header, nil
}
func (f *nativeGitFetch) json(endpoint string, limit int) (any, http.Header, error) {
	raw, h, err := f.get(endpoint, limit, true)
	if err != nil {
		return nil, nil, err
	}
	v, err := nativeGitJSON(raw, limit, f.secret, &f.work)
	return v, h, err
}
func nativeGitMap(v any, required []string, optional ...string) (map[string]any, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, ErrNativeEvidenceInvalid
	}
	allowed := map[string]bool{}
	for _, k := range required {
		if _, ok = m[k]; !ok {
			return nil, ErrNativeEvidenceInvalid
		}
		allowed[k] = true
	}
	for _, k := range optional {
		allowed[k] = true
	}
	for k := range m {
		if !allowed[k] {
			return nil, ErrNativeEvidenceInvalid
		}
	}
	return m, nil
}
func nativeGitInteger(v any, max int) (int, error) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, ErrNativeEvidenceInvalid
	}
	text := string(n)
	i, err := strconv.ParseInt(text, 10, 64)
	if err != nil || i < 0 || i > int64(max) || strconv.FormatInt(i, 10) != text {
		return 0, ErrNativeEvidenceInvalid
	}
	return int(i), nil
}
func (f *nativeGitFetch) checkCommit() error {
	suffix := "/git/commits/" + f.source.commit
	if f.source.provider == "gitlab" {
		suffix = "/commits/" + f.source.commit
	}
	v, _, err := f.json(f.apiPath(suffix), nativeGitMetadataMax)
	if err != nil {
		return err
	}
	if f.source.provider == "github" {
		m, e := nativeGitMap(v, []string{"sha", "tree"}, "node_id", "url", "html_url", "author", "committer", "message", "parents", "verification")
		if e != nil || m["sha"] != f.source.commit {
			return ErrNativeEvidenceInvalid
		}
		tree, e := nativeGitMap(m["tree"], []string{"sha"}, "url")
		if e != nil || tree["sha"] != f.source.tree {
			return ErrNativeEvidenceInvalid
		}
	} else {
		m, e := nativeGitMap(v, []string{"id"}, "short_id", "created_at", "parent_ids", "title", "message", "author_name", "author_email", "authored_date", "committer_name", "committer_email", "committed_date", "trailers", "extended_trailers", "web_url", "stats", "last_pipeline", "status", "project_id")
		if e != nil || m["id"] != f.source.commit {
			return ErrNativeEvidenceInvalid
		}
	}
	return nil
}
func (f *nativeGitFetch) object(oid string) error {
	if !nativeGitOID(oid) {
		return ErrNativeEvidenceInvalid
	}
	if f.seenObjects[oid] {
		return nil
	}
	if f.objects >= nativeGitObjectsMax {
		return ErrNativeEvidenceInvalid
	}
	if err := f.work.charge(256); err != nil {
		return err
	}
	f.objects++
	f.seenObjects[oid] = true
	return nil
}
func (f *nativeGitFetch) blob(oid string, limit int) ([]byte, error) {
	if cached, ok := f.blobs[oid]; ok {
		if len(cached) > limit {
			return nil, ErrNativeEvidenceInvalid
		}
		return cached, nil
	}
	if err := f.object(oid); err != nil {
		return nil, err
	}
	var raw []byte
	if f.source.provider == "github" {
		v, _, err := f.json(f.apiPath("/git/blobs/"+oid), nativeGitBlobJSONMax)
		if err != nil {
			return nil, err
		}
		m, err := nativeGitMap(v, []string{"sha", "size", "encoding", "content"}, "node_id", "url")
		if err != nil || m["sha"] != oid || m["encoding"] != "base64" {
			return nil, ErrNativeEvidenceInvalid
		}
		size, err := nativeGitInteger(m["size"], limit)
		text, ok := m["content"].(string)
		if err != nil || !ok || len(text) > base64.StdEncoding.EncodedLen(limit)+limit/40+1024 {
			return nil, ErrNativeEvidenceInvalid
		}
		if err = f.work.charge(2048 + 2*int64(len(text)) + int64(size)); err != nil {
			return nil, err
		}
		raw = make([]byte, size)
		decoder := base64.NewDecoder(base64.StdEncoding.Strict(), strings.NewReader(text))
		if _, err = io.ReadFull(decoder, raw); err != nil {
			return nil, ErrNativeEvidenceInvalid
		}
		var extra [1]byte
		n, e := decoder.Read(extra[:])
		if n != 0 || e != io.EOF {
			return nil, ErrNativeEvidenceInvalid
		}
	} else {
		var err error
		raw, _, err = f.get(f.apiPath("/blobs/"+oid+"/raw"), limit, false)
		if err != nil {
			return nil, err
		}
	}
	if err := nativeGitVerifyObject("blob", raw, oid, &f.work); err != nil {
		return nil, err
	}
	f.blobs[oid] = raw
	return raw, nil
}
