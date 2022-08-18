# Kryptografie in Go

Quellcode zum Artikel von Reinhard Wobst

iX-Developer-Sonderheft __Programmiersprachen – Next Generation__, 2022

# iX-tract

* Die Programmiersprache Go enthält in ihren Standardpaketen grundlegende Funktionen zur Verschlüsselung von Daten.

* Die Implementierung ist einfach und performant.

* Im Paket crypto/cipher ist der Galois Counter Mode für alle Algorithmen enthalten. Er chiffriert per Counter Mode und bindet eine Prüfsumme ein.
