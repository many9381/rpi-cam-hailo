# OSD font

`NanumGothicBold.ttf` is embedded into the firmware binary (see
`src/media/OsdFontData.S.in`) and rasterized with stb_truetype to draw the
on-screen display. It covers Latin plus all 11,172 modern Hangul syllables.

- Source: Debian package `fonts-nanum` 20200506-1 (trixie/main), file
  `usr/share/fonts/truetype/nanum/NanumGothicBold.ttf`
- Size: 4,642,244 bytes
- SHA-256: 454eb3f503f377782a99eb84fc4bb7dde22a0f075d41b47427737f2985053bc9
- License: SIL Open Font License 1.1 (`OFL.txt`), Copyright 2010 NAVER
  Corporation. The reserved font names are not used for any modified font;
  the file is bundled unmodified.
