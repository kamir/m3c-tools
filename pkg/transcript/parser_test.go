package transcript

import "testing"

func TestParseCaptionsFromJSON_IsTranslatableFalse(t *testing.T) {
	captions := map[string]any{
		"playerCaptionsTracklistRenderer": map[string]any{
			"captionTracks": []any{
				map[string]any{
					"languageCode":   "en",
					"baseUrl":        "https://example.com/captions",
					"isTranslatable": false,
				},
			},
		},
	}
	infos, err := ParseCaptionsFromJSON(captions, "dQw4w9WgXcQ")
	if err != nil {
		t.Fatalf("ParseCaptionsFromJSON: %v", err)
	}
	if len(infos) != 1 {
		t.Fatalf("len(infos)=%d, want 1", len(infos))
	}
	if infos[0].IsTranslatable {
		t.Fatal("isTranslatable:false must not be treated as true")
	}
}

func TestParseCaptionsFromJSON_IsTranslatableTrue(t *testing.T) {
	captions := map[string]any{
		"playerCaptionsTracklistRenderer": map[string]any{
			"captionTracks": []any{
				map[string]any{
					"languageCode":   "en",
					"baseUrl":        "https://example.com/captions",
					"isTranslatable": true,
				},
			},
		},
	}
	infos, err := ParseCaptionsFromJSON(captions, "dQw4w9WgXcQ")
	if err != nil {
		t.Fatalf("ParseCaptionsFromJSON: %v", err)
	}
	if !infos[0].IsTranslatable {
		t.Fatal("isTranslatable:true must stay true")
	}
}

func TestParseCaptionXML_StripsTagsByDefault(t *testing.T) {
	xmlData := `<transcript><text start="0.0" dur="1.0">Hello &lt;b&gt;World&lt;/b&gt;</text></transcript>`
	snippets, err := ParseCaptionXML(xmlData)
	if err != nil {
		t.Fatalf("ParseCaptionXML: %v", err)
	}
	if len(snippets) != 1 {
		t.Fatalf("len=%d, want 1", len(snippets))
	}
	if snippets[0].Text != "Hello World" {
		t.Errorf("text = %q, want stripped tags", snippets[0].Text)
	}
}

func TestParseCaptionXML_PreserveFormatting(t *testing.T) {
	xmlData := `<transcript><text start="0.0" dur="1.0">Hello &lt;b&gt;World&lt;/b&gt;</text></transcript>`
	snippets, err := ParseCaptionXMLFormatting(xmlData, true)
	if err != nil {
		t.Fatalf("ParseCaptionXMLFormatting: %v", err)
	}
	if len(snippets) != 1 {
		t.Fatalf("len=%d, want 1", len(snippets))
	}
	if snippets[0].Text != "Hello <b>World</b>" {
		t.Errorf("text = %q, want tags kept", snippets[0].Text)
	}
}
