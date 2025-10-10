
import os
import pytest

from siemrules.worker import pdf_converter

@pytest.mark.parametrize(
    'file',
    [
        'tests/example_files/file-sample_100kB.doc',
        'tests/example_files/sample.txt',
        'tests/example_files/sample.md',
    ]
)
def test_make_conversion(file):
    output_path = "/tmp/outfile.pdf"
    result = pdf_converter.make_conversion(file, output_path)
    with open(output_path, 'rb') as ff:
        assert tuple(ff.read(4)) == (0x25,0x50,0x44,0x46)
    os.remove(output_path)
