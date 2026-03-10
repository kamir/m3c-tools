package transcript

// LanguageFlag maps an ISO 639-1 language code to a flag emoji representing
// the language's primary country of origin. Used for display in CLI output
// and menu bar transcript listings.
//
// Flag emojis are encoded as regional indicator symbol pairs (U+1F1E6..U+1F1FF).
var LanguageFlag = map[string]string{
	"af":    "🇿🇦", // Afrikaans — South Africa
	"am":    "🇪🇹", // Amharic — Ethiopia
	"ar":    "🇸🇦", // Arabic — Saudi Arabia
	"az":    "🇦🇿", // Azerbaijani — Azerbaijan
	"be":    "🇧🇾", // Belarusian — Belarus
	"bg":    "🇧🇬", // Bulgarian — Bulgaria
	"bn":    "🇧🇩", // Bengali — Bangladesh
	"bs":    "🇧🇦", // Bosnian — Bosnia and Herzegovina
	"ca":    "🇪🇸", // Catalan — Spain
	"ceb":   "🇵🇭", // Cebuano — Philippines
	"cs":    "🇨🇿", // Czech — Czech Republic
	"cy":    "🏴\U000E0067\U000E0062\U000E0077\U000E006C\U000E0073\U000E007F", // Welsh — Wales
	"da":    "🇩🇰", // Danish — Denmark
	"de":    "🇩🇪", // German — Germany
	"el":    "🇬🇷", // Greek — Greece
	"en":    "🇬🇧", // English — United Kingdom
	"en-US": "🇺🇸", // English (US) — United States
	"en-GB": "🇬🇧", // English (UK) — United Kingdom
	"en-AU": "🇦🇺", // English (AU) — Australia
	"en-CA": "🇨🇦", // English (CA) — Canada
	"en-IN": "🇮🇳", // English (IN) — India
	"eo":    "🏳️",   // Esperanto — no country flag
	"es":    "🇪🇸", // Spanish — Spain
	"es-MX": "🇲🇽", // Spanish (Mexico) — Mexico
	"es-419":"🇲🇽", // Spanish (Latin America) — Mexico (representative)
	"et":    "🇪🇪", // Estonian — Estonia
	"eu":    "🇪🇸", // Basque — Spain
	"fa":    "🇮🇷", // Persian — Iran
	"fi":    "🇫🇮", // Finnish — Finland
	"fil":   "🇵🇭", // Filipino — Philippines
	"fr":    "🇫🇷", // French — France
	"fr-CA": "🇨🇦", // French (Canada) — Canada
	"ga":    "🇮🇪", // Irish — Ireland
	"gl":    "🇪🇸", // Galician — Spain
	"gu":    "🇮🇳", // Gujarati — India
	"ha":    "🇳🇬", // Hausa — Nigeria
	"haw":   "🇺🇸", // Hawaiian — United States
	"he":    "🇮🇱", // Hebrew — Israel
	"hi":    "🇮🇳", // Hindi — India
	"hmn":   "🇱🇦", // Hmong — Laos
	"hr":    "🇭🇷", // Croatian — Croatia
	"ht":    "🇭🇹", // Haitian Creole — Haiti
	"hu":    "🇭🇺", // Hungarian — Hungary
	"hy":    "🇦🇲", // Armenian — Armenia
	"id":    "🇮🇩", // Indonesian — Indonesia
	"ig":    "🇳🇬", // Igbo — Nigeria
	"is":    "🇮🇸", // Icelandic — Iceland
	"it":    "🇮🇹", // Italian — Italy
	"iw":    "🇮🇱", // Hebrew (legacy code) — Israel
	"ja":    "🇯🇵", // Japanese — Japan
	"jv":    "🇮🇩", // Javanese — Indonesia
	"ka":    "🇬🇪", // Georgian — Georgia
	"kk":    "🇰🇿", // Kazakh — Kazakhstan
	"km":    "🇰🇭", // Khmer — Cambodia
	"kn":    "🇮🇳", // Kannada — India
	"ko":    "🇰🇷", // Korean — South Korea
	"ku":    "🇮🇶", // Kurdish — Iraq
	"ky":    "🇰🇬", // Kyrgyz — Kyrgyzstan
	"la":    "🇻🇦", // Latin — Vatican City
	"lb":    "🇱🇺", // Luxembourgish — Luxembourg
	"lo":    "🇱🇦", // Lao — Laos
	"lt":    "🇱🇹", // Lithuanian — Lithuania
	"lv":    "🇱🇻", // Latvian — Latvia
	"mg":    "🇲🇬", // Malagasy — Madagascar
	"mi":    "🇳🇿", // Māori — New Zealand
	"mk":    "🇲🇰", // Macedonian — North Macedonia
	"ml":    "🇮🇳", // Malayalam — India
	"mn":    "🇲🇳", // Mongolian — Mongolia
	"mr":    "🇮🇳", // Marathi — India
	"ms":    "🇲🇾", // Malay — Malaysia
	"mt":    "🇲🇹", // Maltese — Malta
	"my":    "🇲🇲", // Myanmar (Burmese) — Myanmar
	"ne":    "🇳🇵", // Nepali — Nepal
	"nl":    "🇳🇱", // Dutch — Netherlands
	"no":    "🇳🇴", // Norwegian — Norway
	"ny":    "🇲🇼", // Chichewa — Malawi
	"or":    "🇮🇳", // Odia — India
	"pa":    "🇮🇳", // Punjabi — India
	"pl":    "🇵🇱", // Polish — Poland
	"ps":    "🇦🇫", // Pashto — Afghanistan
	"pt":    "🇵🇹", // Portuguese — Portugal
	"pt-BR": "🇧🇷", // Portuguese (Brazil) — Brazil
	"ro":    "🇷🇴", // Romanian — Romania
	"ru":    "🇷🇺", // Russian — Russia
	"rw":    "🇷🇼", // Kinyarwanda — Rwanda
	"sd":    "🇵🇰", // Sindhi — Pakistan
	"si":    "🇱🇰", // Sinhala — Sri Lanka
	"sk":    "🇸🇰", // Slovak — Slovakia
	"sl":    "🇸🇮", // Slovenian — Slovenia
	"sm":    "🇼🇸", // Samoan — Samoa
	"sn":    "🇿🇼", // Shona — Zimbabwe
	"so":    "🇸🇴", // Somali — Somalia
	"sq":    "🇦🇱", // Albanian — Albania
	"sr":    "🇷🇸", // Serbian — Serbia
	"st":    "🇱🇸", // Sesotho — Lesotho
	"su":    "🇮🇩", // Sundanese — Indonesia
	"sv":    "🇸🇪", // Swedish — Sweden
	"sw":    "🇹🇿", // Swahili — Tanzania
	"ta":    "🇮🇳", // Tamil — India
	"te":    "🇮🇳", // Telugu — India
	"tg":    "🇹🇯", // Tajik — Tajikistan
	"th":    "🇹🇭", // Thai — Thailand
	"tk":    "🇹🇲", // Turkmen — Turkmenistan
	"tl":    "🇵🇭", // Tagalog — Philippines
	"tr":    "🇹🇷", // Turkish — Turkey
	"tt":    "🇷🇺", // Tatar — Russia
	"ug":    "🇨🇳", // Uyghur — China
	"uk":    "🇺🇦", // Ukrainian — Ukraine
	"ur":    "🇵🇰", // Urdu — Pakistan
	"uz":    "🇺🇿", // Uzbek — Uzbekistan
	"vi":    "🇻🇳", // Vietnamese — Vietnam
	"xh":    "🇿🇦", // Xhosa — South Africa
	"yi":    "🇮🇱", // Yiddish — Israel
	"yo":    "🇳🇬", // Yoruba — Nigeria
	"zh":    "🇨🇳", // Chinese — China
	"zh-CN": "🇨🇳", // Chinese (Simplified) — China
	"zh-Hans":"🇨🇳", // Chinese (Simplified) — China
	"zh-TW": "🇹🇼", // Chinese (Traditional) — Taiwan
	"zh-Hant":"🇹🇼", // Chinese (Traditional) — Taiwan
	"zu":    "🇿🇦", // Zulu — South Africa
}

// FlagForLanguage returns the flag emoji for a language code.
// It first tries an exact match, then falls back to the base language
// (e.g., "en-US" → "en"). Returns defaultFlag if no match is found.
func FlagForLanguage(langCode string) string {
	if flag, ok := LanguageFlag[langCode]; ok {
		return flag
	}
	// Try base language code (strip region/script subtag)
	if idx := indexByte(langCode, '-'); idx >= 0 {
		if flag, ok := LanguageFlag[langCode[:idx]]; ok {
			return flag
		}
	}
	return "🏳️" // white flag as fallback
}

// indexByte returns the index of the first occurrence of c in s, or -1.
func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

// LanguageLabel returns a display label with flag emoji for a transcript.
// Example: "🇬🇧 English (en)" or "🇩🇪 German (de)"
func LanguageLabel(language, langCode string) string {
	flag := FlagForLanguage(langCode)
	return flag + " " + language + " (" + langCode + ")"
}
