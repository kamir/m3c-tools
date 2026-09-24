package trustfreeze

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

var threeProbes = []string{"common.identity", "common.second", "common.zthird"}

func TestVerifyDirCleanCapture(t *testing.T) {
	dir, m := newCapture(t, t.TempDir(), "cap", threeProbes...)
	res := VerifyDir(dir)
	if !res.OK {
		t.Fatalf("clean capture failed: %s", describeFailures(res))
	}
	if res.Kind != KindCapture || res.ContentDigest != m.ContentDigest || res.Manifest == nil {
		t.Fatalf("result = %+v", res)
	}
	if res.Failures == nil || res.Err() != nil {
		t.Fatal("OK result must carry an empty, non-nil failure list and a nil Err")
	}
	// Every persisted file except manifest.json is listed (SPEC-0466 R7).
	onDisk := hashTree(t, dir)
	delete(onDisk, ManifestFile)
	if len(onDisk) != len(m.Files) {
		t.Fatalf("manifest lists %d files, disk has %d", len(m.Files), len(onDisk))
	}
	for _, f := range m.Files {
		if onDisk[f.Path] != f.SHA256 {
			t.Fatalf("%s: manifest sha %s, disk %s", f.Path, f.SHA256, onDisk[f.Path])
		}
	}
}

// TestVerifyDirTamper covers SPEC-0466 TF01-AC3, TF01-AC4 and the tamper list
// of SPEC-0470 TF05-R5 that the core can detect without a signature.
func TestVerifyDirTamper(t *testing.T) {
	middle := "probes/common.second.json"
	cases := []struct {
		name   string
		mutate func(t *testing.T, dir string)
		reason IntegrityReason
		path   string
	}{
		{"byte flip", func(t *testing.T, dir string) {
			p := filepath.Join(dir, filepath.FromSlash(middle))
			b, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			b[len(b)/2] ^= 0x01
			writeRaw(t, dir, middle, b)
		}, IntegrityDigestMismatch, middle},
		{"appended byte", func(t *testing.T, dir string) {
			b, _ := os.ReadFile(filepath.Join(dir, filepath.FromSlash(middle)))
			writeRaw(t, dir, middle, append(b, ' '))
		}, IntegritySizeMismatch, middle},
		{"TF01-AC3 middle file deleted", func(t *testing.T, dir string) {
			if err := os.Remove(filepath.Join(dir, filepath.FromSlash(middle))); err != nil {
				t.Fatal(err)
			}
		}, IntegrityMissing, middle},
		{"empty evidence file deleted", func(t *testing.T, dir string) {
			if err := os.Remove(filepath.Join(dir, "evidence", "common.second", "stdout")); err != nil {
				t.Fatal(err)
			}
		}, IntegrityMissing, "evidence/common.second/stdout"},
		{"rename leaves missing", func(t *testing.T, dir string) {
			if err := os.Rename(filepath.Join(dir, filepath.FromSlash(middle)), filepath.Join(dir, "probes", "common.renamed.json")); err != nil {
				t.Fatal(err)
			}
		}, IntegrityMissing, middle},
		{"rename leaves extra", func(t *testing.T, dir string) {
			if err := os.Rename(filepath.Join(dir, filepath.FromSlash(middle)), filepath.Join(dir, "probes", "common.renamed.json")); err != nil {
				t.Fatal(err)
			}
		}, IntegrityExtra, "probes/common.renamed.json"},
		{"TF01-AC4 unexpected extra file", func(t *testing.T, dir string) {
			writeRaw(t, dir, "notes.txt", []byte("hello"))
		}, IntegrityExtra, "notes.txt"},
		{"TF01-AC4 extra file under signatures in capture is extra", func(t *testing.T, dir string) {
			writeRaw(t, dir, "signatures/other.json", []byte("{}"))
		}, IntegrityExtra, "signatures/other.json"},
		{"TF01-AC4 extra file under signatures in capture violates layout", func(t *testing.T, dir string) {
			writeRaw(t, dir, "signatures/other.json", []byte("{}"))
		}, IntegrityKindLayoutViolation, "signatures/other.json"},
		{"extra empty directory", func(t *testing.T, dir string) {
			if err := os.MkdirAll(filepath.Join(dir, "state", "empty"), 0o700); err != nil {
				t.Fatal(err)
			}
		}, IntegrityExtra, "state/empty/"},
		{"signature file in a capture", func(t *testing.T, dir string) {
			writeRaw(t, dir, SignatureFile, []byte("{}"))
		}, IntegrityKindLayoutViolation, SignatureFile},
		{"unlisted approval.json in a capture", func(t *testing.T, dir string) {
			writeRaw(t, dir, ApprovalFile, []byte("{}"))
		}, IntegrityKindLayoutViolation, ApprovalFile},
		{"manifested approval.json in a capture", func(t *testing.T, dir string) {
			writeRaw(t, dir, ApprovalFile, []byte("{}"))
			rewriteManifest(t, dir, true, func(m *Manifest) {
				m.Files = append(m.Files, FileEntry{Path: ApprovalFile, Size: 2, SHA256: SHA256Hex([]byte("{}"))})
				sortEntries(m.Files)
			})
		}, IntegrityKindLayoutViolation, ApprovalFile},
		{"capture.json removed and unlisted", func(t *testing.T, dir string) {
			if err := os.Remove(filepath.Join(dir, CaptureFile)); err != nil {
				t.Fatal(err)
			}
			rewriteManifest(t, dir, true, func(m *Manifest) { m.Files = dropEntry(m.Files, CaptureFile) })
		}, IntegrityKindLayoutViolation, CaptureFile},
		{"duplicate entry", func(t *testing.T, dir string) {
			rewriteManifest(t, dir, true, func(m *Manifest) {
				m.Files = append(m.Files, entryFor(m.Files, middle))
				sortEntries(m.Files)
			})
		}, IntegrityDuplicatePath, middle},
		{"case-only duplicate entry", func(t *testing.T, dir string) {
			rewriteManifest(t, dir, true, func(m *Manifest) {
				e := entryFor(m.Files, middle)
				e.Path = "probes/Common.Second.json"
				m.Files = append(m.Files, e)
				sortEntries(m.Files)
			})
		}, IntegrityDuplicatePath, "probes/common.second.json"},
		{"traversal entry", func(t *testing.T, dir string) {
			rewriteManifest(t, dir, true, func(m *Manifest) {
				m.Files = append(m.Files, FileEntry{Path: "../outside.json", Size: 2, SHA256: SHA256Hex([]byte("{}"))})
			})
		}, IntegrityBadPath, "../outside.json"},
		{"absolute entry", func(t *testing.T, dir string) {
			rewriteManifest(t, dir, true, func(m *Manifest) {
				m.Files = append(m.Files, FileEntry{Path: "/etc/passwd", Size: 1, SHA256: SHA256Hex([]byte("x"))})
			})
		}, IntegrityBadPath, "/etc/passwd"},
		{"drive letter entry", func(t *testing.T, dir string) {
			rewriteManifest(t, dir, true, func(m *Manifest) {
				m.Files = append(m.Files, FileEntry{Path: "C:/Windows/win.ini", Size: 1, SHA256: SHA256Hex([]byte("x"))})
			})
		}, IntegrityBadPath, "C:/Windows/win.ini"},
		{"UNC entry", func(t *testing.T, dir string) {
			rewriteManifest(t, dir, true, func(m *Manifest) {
				m.Files = append(m.Files, FileEntry{Path: "//server/share/x", Size: 1, SHA256: SHA256Hex([]byte("x"))})
			})
		}, IntegrityBadPath, "//server/share/x"},
		{"backslash entry", func(t *testing.T, dir string) {
			rewriteManifest(t, dir, true, func(m *Manifest) {
				for i := range m.Files {
					if m.Files[i].Path == middle {
						m.Files[i].Path = `probes\common.second.json`
					}
				}
			})
		}, IntegrityBadPath, `probes\common.second.json`},
		{"reserved entry", func(t *testing.T, dir string) {
			rewriteManifest(t, dir, true, func(m *Manifest) {
				m.Files = append(m.Files, FileEntry{Path: ManifestFile, Size: 1, SHA256: SHA256Hex([]byte("x"))})
				sortEntries(m.Files)
			})
		}, IntegrityBadPath, ManifestFile},
		{"entry substitution", func(t *testing.T, dir string) {
			rewriteManifest(t, dir, true, func(m *Manifest) {
				other := entryFor(m.Files, "probes/common.zthird.json")
				for i := range m.Files {
					if m.Files[i].Path == middle {
						m.Files[i].Size, m.Files[i].SHA256 = other.Size, other.SHA256
					}
				}
			})
		}, IntegrityDigestMismatch, middle},
		{"unsorted entries", func(t *testing.T, dir string) {
			rewriteManifest(t, dir, true, func(m *Manifest) {
				m.Files[0], m.Files[1] = m.Files[1], m.Files[0]
			})
		}, IntegrityManifestInvalid, ""},
		{"malformed sha256", func(t *testing.T, dir string) {
			rewriteManifest(t, dir, true, func(m *Manifest) {
				for i := range m.Files {
					if m.Files[i].Path == middle {
						m.Files[i].SHA256 = strings.ToUpper(m.Files[i].SHA256)
					}
				}
			})
		}, IntegrityManifestInvalid, middle},
		{"content digest: subject changed", func(t *testing.T, dir string) {
			rewriteManifest(t, dir, false, func(m *Manifest) { m.Subject.ID = SubjectID("linux", "host-b.example") })
		}, IntegrityContentDigestMismatch, ManifestFile},
		{"content digest: file entry changed", func(t *testing.T, dir string) {
			b, _ := os.ReadFile(filepath.Join(dir, filepath.FromSlash(middle)))
			b = append(b, ' ')
			writeRaw(t, dir, middle, b)
			rewriteManifest(t, dir, false, func(m *Manifest) {
				for i := range m.Files {
					if m.Files[i].Path == middle {
						m.Files[i].Size, m.Files[i].SHA256 = int64(len(b)), SHA256Hex(b)
					}
				}
			})
		}, IntegrityContentDigestMismatch, ManifestFile},
		{"unknown kind", func(t *testing.T, dir string) {
			// MarshalFile refuses an unknown kind, so the attacker edits text.
			b, _ := os.ReadFile(filepath.Join(dir, ManifestFile))
			s := strings.Replace(string(b), `"kind": "capture"`, `"kind": "snapshot"`, 1)
			if s == string(b) {
				t.Fatal("fixture manifest has no kind line")
			}
			writeRaw(t, dir, ManifestFile, []byte(s))
		}, IntegrityUnknownKind, ManifestFile},
		{"kind rewritten to baseline", func(t *testing.T, dir string) {
			rewriteManifest(t, dir, true, func(m *Manifest) { m.Kind = KindBaseline })
		}, IntegrityKindLayoutViolation, ApprovalFile},
		{"unknown schema", func(t *testing.T, dir string) {
			rewriteManifest(t, dir, true, func(m *Manifest) { m.SchemaVersion = "trust-freeze/manifest/v2" })
		}, IntegrityUnknownSchema, ManifestFile},
		{"manifest missing", func(t *testing.T, dir string) {
			if err := os.Remove(filepath.Join(dir, ManifestFile)); err != nil {
				t.Fatal(err)
			}
		}, IntegrityMissing, ManifestFile},
		{"manifest not canonical", func(t *testing.T, dir string) {
			b, _ := os.ReadFile(filepath.Join(dir, ManifestFile))
			writeRaw(t, dir, ManifestFile, append([]byte(" "), b...))
		}, IntegrityManifestInvalid, ManifestFile},
		{"manifest with CRLF", func(t *testing.T, dir string) {
			b, _ := os.ReadFile(filepath.Join(dir, ManifestFile))
			writeRaw(t, dir, ManifestFile, []byte(strings.ReplaceAll(string(b), "\n", "\r\n")))
		}, IntegrityManifestInvalid, ManifestFile},
		{"manifest with unknown field", func(t *testing.T, dir string) {
			b, _ := os.ReadFile(filepath.Join(dir, ManifestFile))
			s := strings.Replace(string(b), "\"bundle_id\"", "\"extra\": \"x\",\n  \"bundle_id\"", 1)
			writeRaw(t, dir, ManifestFile, []byte(s))
		}, IntegrityManifestInvalid, ManifestFile},
		{"manifest not JSON", func(t *testing.T, dir string) {
			writeRaw(t, dir, ManifestFile, []byte("not json"))
		}, IntegrityManifestInvalid, ManifestFile},
		{"non-canonical file name on disk", func(t *testing.T, dir string) {
			writeRaw(t, dir, "bad name.json", []byte("{}"))
		}, IntegrityBadPath, "bad name.json"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir, _ := newCapture(t, t.TempDir(), "cap", threeProbes...)
			tc.mutate(t, dir)
			res := VerifyDir(dir)
			requireFailure(t, res, tc.reason, tc.path)
			if res.Err() == nil {
				t.Fatal("Err() must be non-nil for a failed result")
			}
			if _, err := ReadBundle(dir); err == nil {
				t.Fatal("ReadBundle accepted a tampered bundle")
			}
		})
	}
}

// TestVerifyDirSymlinks: a symlink anywhere in the bundle is a failure, and
// VerifyDir never follows it (SPEC-0466 R7).
func TestVerifyDirSymlinks(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, dir, outside string) error
		path  string
	}{
		{"symlink file inside", func(t *testing.T, dir, outside string) error {
			return os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(dir, "probes", "link.json"))
		}, "probes/link.json"},
		{"manifested file replaced by symlink", func(t *testing.T, dir, outside string) error {
			p := filepath.Join(dir, "probes", "common.second.json")
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(outside, "copy.json"), b, 0o600); err != nil {
				return err
			}
			if err := os.Remove(p); err != nil {
				return err
			}
			return os.Symlink(filepath.Join(outside, "copy.json"), p)
		}, "probes/common.second.json"},
		{"symlink directory inside", func(t *testing.T, dir, outside string) error {
			return os.Symlink(outside, filepath.Join(dir, "state", "outside"))
		}, "state/outside"},
		{"manifest.json is a symlink", func(t *testing.T, dir, outside string) error {
			p := filepath.Join(dir, ManifestFile)
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			if err := os.WriteFile(filepath.Join(outside, "manifest.json"), b, 0o600); err != nil {
				return err
			}
			if err := os.Remove(p); err != nil {
				return err
			}
			return os.Symlink(filepath.Join(outside, "manifest.json"), p)
		}, ManifestFile},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parent := t.TempDir()
			outside := t.TempDir()
			if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("outside"), 0o600); err != nil {
				t.Fatal(err)
			}
			dir, _ := newCapture(t, parent, "cap", threeProbes...)
			if err := tc.setup(t, dir, outside); err != nil {
				t.Skipf("cannot create a symlink on this host: %v", err)
			}
			requireFailure(t, VerifyDir(dir), IntegritySymlink, tc.path)
		})
	}
	t.Run("bundle root is a symlink", func(t *testing.T) {
		parent := t.TempDir()
		dir, _ := newCapture(t, parent, "cap", threeProbes...)
		link := filepath.Join(parent, "link")
		if err := os.Symlink(dir, link); err != nil {
			t.Skipf("cannot create a symlink on this host: %v", err)
		}
		requireFailure(t, VerifyDir(link), IntegritySymlink, ".")
	})
}

func TestVerifyDirBaseline(t *testing.T) {
	parent := t.TempDir()
	capDir, capM := newCapture(t, parent, "cap", threeProbes...)
	before := hashTree(t, capDir)
	baseDir := filepath.Join(parent, "base")
	bm := newBaseline(t, capDir, capM, baseDir)
	if res := VerifyDir(baseDir); !res.OK {
		t.Fatalf("baseline failed: %s", describeFailures(res))
	}
	if !reflect.DeepEqual(before, hashTree(t, capDir)) {
		t.Fatal("building a baseline modified the capture directory")
	}
	// Copied files are byte-identical (SPEC-0470 TF05-R2).
	for _, f := range capM.Files {
		if entryFor(bm.Files, f.Path) != f {
			t.Fatalf("%s not copied byte-identically", f.Path)
		}
	}
	if bm.Kind != KindBaseline || entryFor(bm.Files, ApprovalFile).Path != ApprovalFile {
		t.Fatalf("baseline manifest = %+v", bm)
	}
	if entryFor(bm.Files, SignatureFile).Path != "" {
		t.Fatal("the signature file must not be listed in the manifest")
	}

	cases := []struct {
		name   string
		mutate func(t *testing.T, dir string)
		reason IntegrityReason
		path   string
	}{
		{"signature removed", func(t *testing.T, dir string) {
			if err := os.Remove(filepath.Join(dir, filepath.FromSlash(SignatureFile))); err != nil {
				t.Fatal(err)
			}
		}, IntegrityKindLayoutViolation, SignatureFile},
		{"extra file under signatures", func(t *testing.T, dir string) {
			writeRaw(t, dir, "signatures/second.ed25519.json", []byte("{}"))
		}, IntegrityExtra, "signatures/second.ed25519.json"},
		// SPEC-0470 section 4.4 step 3: nothing but the one signature file under
		// signatures/, also when an attacker manifests a second one.
		{"manifested second file under signatures", func(t *testing.T, dir string) {
			b := []byte("{}\n")
			writeRaw(t, dir, "signatures/manifest.ed25519.json.bak", b)
			rewriteManifest(t, dir, true, func(m *Manifest) {
				m.Files = append(m.Files, FileEntry{Path: "signatures/manifest.ed25519.json.bak", Size: int64(len(b)), SHA256: SHA256Hex(b)})
				sortEntries(m.Files)
			})
		}, IntegrityKindLayoutViolation, "signatures/manifest.ed25519.json.bak"},
		{"approval removed and unlisted", func(t *testing.T, dir string) {
			if err := os.Remove(filepath.Join(dir, ApprovalFile)); err != nil {
				t.Fatal(err)
			}
			rewriteManifest(t, dir, true, func(m *Manifest) { m.Files = dropEntry(m.Files, ApprovalFile) })
		}, IntegrityKindLayoutViolation, ApprovalFile},
		{"approval modified", func(t *testing.T, dir string) {
			b, err := os.ReadFile(filepath.Join(dir, ApprovalFile))
			if err != nil {
				t.Fatal(err)
			}
			same := strings.Replace(string(b), "charlie", "charlix", 1)
			if len(same) != len(b) || same == string(b) {
				t.Fatal("fixture no longer contains the reviewer name")
			}
			writeRaw(t, dir, ApprovalFile, []byte(same))
		}, IntegrityDigestMismatch, ApprovalFile},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := t.TempDir()
			c, cm := newCapture(t, p, "cap", threeProbes...)
			b := filepath.Join(p, "base")
			newBaseline(t, c, cm, b)
			tc.mutate(t, b)
			requireFailure(t, VerifyDir(b), tc.reason, tc.path)
		})
	}
}

// TestContentDigestCoversEveryManifestField mutates every manifest field and
// requires a different digest; a reflection check makes sure no field can be
// hidden from the canonical form.
func TestContentDigestCoversEveryManifestField(t *testing.T) {
	base := Manifest{
		SchemaVersion: SchemaManifest, Kind: KindCapture, BundleID: "b", CreatedAt: FormatTime(testTime),
		Subject: testSubject(), BundlePolicy: BundlePolicy{RejectAdditions: true},
		Files: []FileEntry{{Path: "capture.json", Size: 1, SHA256: SHA256Hex([]byte("x"))}},
	}
	want, err := ComputeContentDigest(base)
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*Manifest){
		"schema_version":   func(m *Manifest) { m.SchemaVersion = SchemaCapture },
		"kind":             func(m *Manifest) { m.Kind = KindBaseline },
		"bundle_id":        func(m *Manifest) { m.BundleID = "c" },
		"created_at":       func(m *Manifest) { m.CreatedAt = "2026-01-02T03:04:06Z" },
		"subject.id":       func(m *Manifest) { m.Subject.ID = "device/0000000000000000" },
		"subject.os":       func(m *Manifest) { m.Subject.OSFamily = "darwin" },
		"reject_additions": func(m *Manifest) { m.BundlePolicy.RejectAdditions = false },
		"file path":        func(m *Manifest) { m.Files[0].Path = "capture2.json" },
		"file size":        func(m *Manifest) { m.Files[0].Size = 2 },
		"file sha256":      func(m *Manifest) { m.Files[0].SHA256 = SHA256Hex([]byte("y")) },
		"file added":       func(m *Manifest) { m.Files = append(m.Files, FileEntry{Path: "z", Size: 0, SHA256: SHA256Hex(nil)}) },
		"file removed":     func(m *Manifest) { m.Files = []FileEntry{} },
	}
	for name, mut := range mutations {
		m := base
		m.Files = append([]FileEntry(nil), base.Files...)
		mut(&m)
		got, err := ComputeContentDigest(m)
		if err != nil {
			t.Fatal(err)
		}
		if got == want {
			t.Errorf("mutating %s did not change the content digest", name)
		}
	}
	// The declared digest itself is excluded from its own preimage.
	withDigest := base
	withDigest.ContentDigest = "sha256:anything"
	if got, _ := ComputeContentDigest(withDigest); got != want {
		t.Fatal("content_digest must be ignored when computing itself")
	}
	var check func(rt reflect.Type)
	check = func(rt reflect.Type) {
		for i := 0; i < rt.NumField(); i++ {
			f := rt.Field(i)
			if !f.IsExported() || f.Tag.Get("json") == "-" || strings.Contains(f.Tag.Get("json"), "omitempty") {
				t.Errorf("%s.%s is hidden from or optional in the canonical form", rt.Name(), f.Name)
			}
			switch f.Type.Kind() {
			case reflect.Struct:
				check(f.Type)
			case reflect.Slice:
				if f.Type.Elem().Kind() == reflect.Struct {
					check(f.Type.Elem())
				}
			}
		}
	}
	check(reflect.TypeOf(Manifest{}))
}

func TestVerifyDirDeterministic(t *testing.T) {
	dir, _ := newCapture(t, t.TempDir(), "cap", threeProbes...)
	writeRaw(t, dir, "z.txt", []byte("z"))
	writeRaw(t, dir, "a.txt", []byte("a"))
	if err := os.Remove(filepath.Join(dir, "probes", "common.zthird.json")); err != nil {
		t.Fatal(err)
	}
	a, b := VerifyDir(dir), VerifyDir(dir)
	ja, err := MarshalCanonical(a)
	if err != nil {
		t.Fatal(err)
	}
	jb, _ := MarshalCanonical(b)
	if string(ja) != string(jb) {
		t.Fatal("two verifications of the same tree differ")
	}
	for i := 1; i < len(a.Failures); i++ {
		p, q := a.Failures[i-1], a.Failures[i]
		if p.Reason > q.Reason || (p.Reason == q.Reason && p.Path > q.Path) {
			t.Fatalf("failures not sorted: %+v", a.Failures)
		}
	}
}

func TestVerifyDirRootProblems(t *testing.T) {
	requireFailure(t, VerifyDir(filepath.Join(t.TempDir(), "absent")), IntegrityUnreadable, ".")
	f := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	requireFailure(t, VerifyDir(f), IntegrityUnreadable, ".")
	requireFailure(t, VerifyDir(t.TempDir()), IntegrityMissing, ManifestFile)
}

func entryFor(files []FileEntry, p string) FileEntry {
	for _, f := range files {
		if f.Path == p {
			return f
		}
	}
	return FileEntry{}
}

func dropEntry(files []FileEntry, p string) []FileEntry {
	out := []FileEntry{}
	for _, f := range files {
		if f.Path != p {
			out = append(out, f)
		}
	}
	return out
}

func sortEntries(files []FileEntry) {
	for i := 1; i < len(files); i++ {
		for j := i; j > 0 && files[j-1].Path > files[j].Path; j-- {
			files[j-1], files[j] = files[j], files[j-1]
		}
	}
}
