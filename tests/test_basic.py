
from src.utils import valid_ip
def test_ip():
    assert valid_ip("1.1.1.1")
    assert not valid_ip("999.1.1.1")
