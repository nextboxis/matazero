import pytest
from imgint.core.diff.comparator import ForensicComparator, MetadataDiff
from imgint.core.pipeline import AnalysisRecord
from imgint.core.model.finding import Finding, Confidence
from imgint.core.model.record import Field

def test_metadata_diff_identical():
    rec_a = AnalysisRecord(file_path="a.jpg", sha256="123", file_size=100, mime_type="image/jpeg", tool_version="1.0", corpus_version="1.0")
    rec_b = AnalysisRecord(file_path="b.jpg", sha256="123", file_size=100, mime_type="image/jpeg", tool_version="1.0", corpus_version="1.0")
    
    rec_a.fields.append(Field(standard="EXIF", name="Make", value="Apple", raw_value=b"Apple", value_type="str"))
    rec_a.fields.append(Field(standard="EXIF", name="Model", value="iPhone 13", raw_value=b"iPhone 13", value_type="str"))
    rec_b.fields.append(Field(standard="EXIF", name="Make", value="Apple", raw_value=b"Apple", value_type="str"))
    rec_b.fields.append(Field(standard="EXIF", name="Model", value="iPhone 13", raw_value=b"iPhone 13", value_type="str"))
    
    diff = ForensicComparator._diff_metadata(rec_a, rec_b)
    
    assert diff.identical_count == 2
    assert len(diff.added) == 0
    assert len(diff.removed) == 0
    assert len(diff.modified) == 0

def test_metadata_diff_modified():
    rec_a = AnalysisRecord(file_path="a.jpg", sha256="123", file_size=100, mime_type="image/jpeg", tool_version="1.0", corpus_version="1.0")
    rec_b = AnalysisRecord(file_path="b.jpg", sha256="456", file_size=100, mime_type="image/jpeg", tool_version="1.0", corpus_version="1.0")
    
    rec_a.fields.append(Field(standard="EXIF", name="Make", value="Apple", raw_value=b"Apple", value_type="str"))
    rec_a.fields.append(Field(standard="EXIF", name="Model", value="iPhone 13", raw_value=b"iPhone 13", value_type="str"))
    rec_a.fields.append(Field(standard="EXIF", name="Software", value="15.0", raw_value=b"15.0", value_type="str"))
    
    rec_b.fields.append(Field(standard="EXIF", name="Make", value="Apple", raw_value=b"Apple", value_type="str"))
    rec_b.fields.append(Field(standard="EXIF", name="Model", value="iPhone 13", raw_value=b"iPhone 13", value_type="str"))
    rec_b.fields.append(Field(standard="EXIF", name="Software", value="16.0", raw_value=b"16.0", value_type="str"))
    rec_b.fields.append(Field(standard="EXIF", name="Lens", value="Wide", raw_value=b"Wide", value_type="str"))
    
    diff = ForensicComparator._diff_metadata(rec_a, rec_b)
    
    assert diff.identical_count == 2
    
    assert len(diff.modified) == 1
    assert diff.modified[0]["field"] == "Software"
    assert diff.modified[0]["value_a"] == "15.0"
    assert diff.modified[0]["value_b"] == "16.0"
    
    assert len(diff.added) == 1
    assert diff.added[0]["field"] == "Lens"
    assert diff.added[0]["value"] == "Wide"

def test_dqt_diff_identical():
    from imgint.core.model.record import StructuralUnit
    rec_a = AnalysisRecord(file_path="a.jpg", sha256="123", file_size=100, mime_type="image/jpeg", tool_version="1.0", corpus_version="1.0")
    rec_b = AnalysisRecord(file_path="b.jpg", sha256="456", file_size=100, mime_type="image/jpeg", tool_version="1.0", corpus_version="1.0")
    
    dqt_payload = bytes([1, 2, 3]*21 + [4])
    rec_a.structural_units.append(StructuralUnit(name="DQT", offset=0, length=64, data_offset=0, data_length=64, payload=dqt_payload))
    rec_b.structural_units.append(StructuralUnit(name="DQT", offset=0, length=64, data_offset=0, data_length=64, payload=dqt_payload))
    
    dist, sim = ForensicComparator._diff_dqt(rec_a, rec_b)
    
    assert dist == 0.0
    assert sim == 100.0
