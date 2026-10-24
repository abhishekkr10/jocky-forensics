import pytest
from backend.app.detection import compile_sigma, Unsupported
from backend.app.core import native

def test_sigma_alternative_field_selections():
    text='''title: Alternative commands
id: 7a31350a-8613-46db-b073-c40b04e01779
status: experimental
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    - Image|endswith: '\\powershell.exe'
    - Image|endswith: '\\pwsh.exe'
  condition: selection
level: medium
'''
    _,predicate=compile_sigma(text)
    result=native("predicate",{"predicate":predicate,"events":[{"Image":"C:\\Windows\\powershell.exe"},{"Image":"C:\\Tools\\pwsh.exe"},{"Image":"C:\\Windows\\notepad.exe"}]})
    assert result["matches"]==[True,True,False]

def test_unsupported_regex_does_not_silently_match():
    text='''title: Unsupported
logsource:
  product: windows
detection:
  selection:
    Image|re: .*shell.*
  condition: selection
'''
    with pytest.raises(Unsupported): compile_sigma(text)
