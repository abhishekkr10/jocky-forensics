rule Jocky_Harmless_Lab_Marker {
  meta:
    description = "Harmless JOCKY lab marker, not malware"
    author = "JOCKY"
  strings:
    $marker = "JOCKY_HARMLESS_FORENSIC_MARKER_V1"
  condition:
    $marker
}
