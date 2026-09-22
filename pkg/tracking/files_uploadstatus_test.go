package tracking

import (
	"path/filepath"
	"testing"
)

// Eine leere DocID ist kein Erfolg. Ohne diese Pruefung schrieb jeder Aufrufer,
// der versehentlich "" uebergab, status='uploaded' ohne upload_doc_id und ohne
// uploaded_at. Auf dem M4 standen so 154 von 612 Zeilen, die einen Upload
// behaupten und nichts benennen, was man nachpruefen koennte.
func TestRecordUploadSuccessLehntLeereDocIDAb(t *testing.T) {
	db := neueDB(t)
	defer db.Close()
	const h, typ = "hash-leer", "plaud"
	if _, err := db.RecordFile("plaud://leer", h, 1, typ, ""); err != nil {
		t.Fatalf("RecordFile: %v", err)
	}

	if err := db.RecordUploadSuccess(h, typ, ""); err == nil {
		t.Fatal("leere docID wurde als Erfolg angenommen")
	}

	f, err := db.GetByHash(h, typ)
	if err != nil || f == nil {
		t.Fatalf("GetByHash: %v", err)
	}
	if f.Status == "uploaded" {
		t.Errorf("Zeile steht auf 'uploaded', obwohl keine DocID vorliegt")
	}
}

func TestRecordUploadSuccessMitDocIDGehtWeiterhin(t *testing.T) {
	db := neueDB(t)
	defer db.Close()
	const h, typ = "hash-gut", "plaud"
	if _, err := db.RecordFile("plaud://gut", h, 1, typ, ""); err != nil {
		t.Fatalf("RecordFile: %v", err)
	}
	if err := db.RecordUploadSuccess(h, typ, "DOC123"); err != nil {
		t.Fatalf("gueltiger Fall abgelehnt: %v", err)
	}
	f, _ := db.GetByHash(h, typ)
	if f == nil || f.Status != "uploaded" || f.UploadDocID != "DOC123" {
		t.Errorf("Erfolgsfall nicht vermerkt: %+v", f)
	}
}

// Ein Fehlschlag muss eine Spur hinterlassen. upload_error stand in 612 Zeilen
// kein einziges Mal, weil der Plaud-Pfad die Funktion nie rief.
func TestRecordUploadErrorHinterlaesstSpur(t *testing.T) {
	db := neueDB(t)
	defer db.Close()
	const h, typ = "hash-fehl", "plaud"
	if _, err := db.RecordFile("plaud://fehl", h, 1, typ, ""); err != nil {
		t.Fatalf("RecordFile: %v", err)
	}
	if err := db.RecordUploadError(h, typ, "upload: 500 vom Server"); err != nil {
		t.Fatalf("RecordUploadError: %v", err)
	}
	f, _ := db.GetByHash(h, typ)
	if f == nil || f.Status != "failed" || f.UploadError == "" {
		t.Errorf("Fehlschlag nicht vermerkt: %+v", f)
	}
}

func neueDB(t *testing.T) *FilesDB {
	t.Helper()
	db, err := OpenFilesDB(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatalf("OpenFilesDB: %v", err)
	}
	return db
}
