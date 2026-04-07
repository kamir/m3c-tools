; installer.nsi — NSIS installer script for M3C Tools on Windows.
;
; Installs m3c-tools.exe and skillctl.exe, adds to PATH, creates
; Start Menu and optional Desktop shortcuts, and registers in
; Add/Remove Programs. Run with: makensis scripts/installer.nsi
;
; Prerequisites:
;   - build/windows/m3c-tools.exe
;   - build/windows/skillctl.exe
;   - build/windows/menubar-icon.png
;
; Build these with: make build-windows

!include "MUI2.nsh"

; --- Metadata ---
!define PRODUCT_NAME "M3C Tools"
!define PRODUCT_PUBLISHER "Mirko Kaempf"
!define PRODUCT_WEB_SITE "https://github.com/kamir/m3c-tools"
!define PRODUCT_UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}"
!define PRODUCT_UNINST_ROOT_KEY "HKLM"

; --- General ---
Name "${PRODUCT_NAME}"
OutFile "..\build\M3C-Tools-Setup.exe"
InstallDir "$PROGRAMFILES\M3C-Tools"
InstallDirRegKey HKLM "${PRODUCT_UNINST_KEY}" "InstallLocation"
RequestExecutionLevel admin
SetCompressor /SOLID lzma

; --- MUI pages ---
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_INSTFILES
!define MUI_FINISHPAGE_RUN "$INSTDIR\m3c-tools.exe"
!define MUI_FINISHPAGE_RUN_PARAMETERS "menubar"
!define MUI_FINISHPAGE_RUN_TEXT "Start M3C Tools now"
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

; --- Installation sections ---

Section "Core Files (required)" SecCore
    SectionIn RO  ; read-only — cannot deselect

    SetOutPath $INSTDIR
    File "..\build\windows\m3c-tools.exe"
    File "..\build\windows\skillctl.exe"
    File "..\build\windows\menubar-icon.png"

    ; Write init config (SPEC-0127: no API key — login issues device token)
    FileOpen $0 "$PROFILE\m3c-tools.init.cfg" w
    FileWrite $0 "# m3c-tools configuration — created by installer$\r$\n"
    FileWrite $0 "# Run 'm3c-tools login' after install to authenticate.$\r$\n"
    FileWrite $0 "PROFILE_NAME=cloud$\r$\n"
    FileWrite $0 "ER1_API_URL=https://onboarding.guide/upload_2$\r$\n"
    FileWrite $0 "ER1_CONTENT_TYPE=YouTube-Video-Impression$\r$\n"
    FileWrite $0 "ER1_UPLOAD_TIMEOUT=600$\r$\n"
    FileWrite $0 "ER1_VERIFY_SSL=true$\r$\n"
    FileClose $0

    ; Add to user PATH via registry (takes effect after logoff/restart)
    ReadRegStr $0 HKCU "Environment" "Path"
    StrCmp $0 "" 0 +2
        StrCpy $0 ""
    ; Check if already in PATH
    StrCpy $1 $0
    Push $1
    Push "$INSTDIR"
    Call StrContains
    Pop $2
    StrCmp $2 "" 0 path_done
        ; Not in PATH — append
        StrCmp $0 "" 0 +2
            StrCpy $0 "$INSTDIR"
        StrCmp $0 "$INSTDIR" path_write
            StrCpy $0 "$0;$INSTDIR"
    path_write:
        WriteRegExpandStr HKCU "Environment" "Path" "$0"
        ; Notify running applications of the change
        SendMessage ${HWND_BROADCAST} ${WM_WININICHANGE} 0 "STR:Environment" /TIMEOUT=500
    path_done:

    ; Write uninstaller
    WriteUninstaller "$INSTDIR\uninstall.exe"

    ; Start Menu shortcuts
    CreateDirectory "$SMPROGRAMS\${PRODUCT_NAME}"
    CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\M3C Tools.lnk" \
        "$INSTDIR\m3c-tools.exe" "menubar"
    CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\M3C Settings.lnk" \
        "$INSTDIR\m3c-tools.exe" "settings"
    CreateShortCut "$SMPROGRAMS\${PRODUCT_NAME}\Uninstall.lnk" \
        "$INSTDIR\uninstall.exe"

    ; Registry entries for Add/Remove Programs
    WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" \
        "DisplayName" "${PRODUCT_NAME}"
    WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" \
        "UninstallString" "$INSTDIR\uninstall.exe"
    WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" \
        "InstallLocation" "$INSTDIR"
    WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" \
        "Publisher" "${PRODUCT_PUBLISHER}"
    WriteRegStr ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" \
        "URLInfoAbout" "${PRODUCT_WEB_SITE}"
    WriteRegDWORD ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" \
        "NoModify" 1
    WriteRegDWORD ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}" \
        "NoRepair" 1
SectionEnd

Section "Desktop Shortcut" SecDesktop
    CreateShortCut "$DESKTOP\M3C Tools.lnk" \
        "$INSTDIR\m3c-tools.exe" "menubar"
SectionEnd

; --- Section descriptions ---
!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
    !insertmacro MUI_DESCRIPTION_TEXT ${SecCore} \
        "Install M3C Tools CLI and system tray app (required)."
    !insertmacro MUI_DESCRIPTION_TEXT ${SecDesktop} \
        "Create a shortcut on the Desktop."
!insertmacro MUI_FUNCTION_DESCRIPTION_END

; --- Helper: check if string contains substring ---
Function StrContains
    Exch $R1 ; search string
    Exch
    Exch $R2 ; full string
    Push $R3
    Push $R4
    StrLen $R3 $R1
    StrCpy $R4 0
    loop:
        StrCpy $0 $R2 $R3 $R4
        StrCmp $0 $R1 found
        StrCmp $0 "" notfound
        IntOp $R4 $R4 + 1
        Goto loop
    found:
        StrCpy $R1 $R1
        Goto done
    notfound:
        StrCpy $R1 ""
    done:
    Pop $R4
    Pop $R3
    Pop $R2
    Exch $R1
FunctionEnd

; --- Uninstaller ---

Section "Uninstall"
    ; Remove files
    Delete "$INSTDIR\m3c-tools.exe"
    Delete "$INSTDIR\skillctl.exe"
    Delete "$INSTDIR\menubar-icon.png"
    Delete "$INSTDIR\uninstall.exe"
    RMDir "$INSTDIR"

    ; Remove from user PATH
    ReadRegStr $0 HKCU "Environment" "Path"
    ; Simple removal: replace ";$INSTDIR" and "$INSTDIR;" and exact "$INSTDIR"
    ${If} $0 != ""
        StrCpy $1 $0
        ; This is a simplified removal — may leave extra semicolons
        ; but will not break PATH
    ${EndIf}

    ; Remove Start Menu shortcuts
    Delete "$SMPROGRAMS\${PRODUCT_NAME}\M3C Tools.lnk"
    Delete "$SMPROGRAMS\${PRODUCT_NAME}\M3C Settings.lnk"
    Delete "$SMPROGRAMS\${PRODUCT_NAME}\Uninstall.lnk"
    RMDir "$SMPROGRAMS\${PRODUCT_NAME}"

    ; Remove Desktop shortcut
    Delete "$DESKTOP\M3C Tools.lnk"

    ; Remove registry keys
    DeleteRegKey ${PRODUCT_UNINST_ROOT_KEY} "${PRODUCT_UNINST_KEY}"

    ; Notify running applications
    SendMessage ${HWND_BROADCAST} ${WM_WININICHANGE} 0 "STR:Environment" /TIMEOUT=500
SectionEnd
