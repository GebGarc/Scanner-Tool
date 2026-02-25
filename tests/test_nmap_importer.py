"""Test Nmap XML importer"""
import pytest
from unittest.mock import MagicMock, patch
from pathlib import Path
import xml.etree.ElementTree as ET
from app.modules.nmap_importer import NmapImporter
from app.services.scope import ScopeValidator

@pytest.fixture
def mock_db():
    return MagicMock()

@pytest.fixture
def mock_scope_validator():
    validator = MagicMock(spec=ScopeValidator)
    validator.is_ip_in_scope.return_value = (True, "In scope")
    validator.is_domain_in_scope.return_value = (True, "In scope")
    return validator

def test_parse_xml_valid(mock_db, mock_scope_validator):
    """Test parsing a valid Nmap XML content"""
    xml_content = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
<host>
<status state="up"/>
<address addr="192.168.1.1" addrtype="ipv4"/>
<hostnames><hostname name="test.local" type="user"/></hostnames>
<ports><port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port></ports>
</host>
</nmaprun>
"""
    importer = NmapImporter(mock_db, mock_scope_validator)
    
    with patch("xml.etree.ElementTree.parse") as mock_parse:
        mock_tree = MagicMock()
        mock_tree.getroot.return_value = ET.fromstring(xml_content)
        mock_parse.return_value = mock_tree
        
        assets, services = importer.parse_xml(Path("dummy.xml"))
        
        assert len(assets) == 1
        assert assets[0]['ip_address'] == "192.168.1.1"
        assert assets[0]['hostname'] == "test.local"
        assert len(services) == 1
        assert services[0]['port'] == 80
        
        # Verify scope validator was called with string
        mock_scope_validator.is_ip_in_scope.assert_called_with("192.168.1.1")

def test_parse_xml_missing_ip(mock_db, mock_scope_validator):
    """Test parsing Nmap XML where IP address is missing but element exists"""
    xml_content = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
<host>
<status state="up"/>
<address addrtype="ipv4"/> <!-- Missing addr attribute -->
</host>
</nmaprun>
"""
    importer = NmapImporter(mock_db, mock_scope_validator)
    
    with patch("xml.etree.ElementTree.parse") as mock_parse:
        mock_tree = MagicMock()
        mock_tree.getroot.return_value = ET.fromstring(xml_content)
        mock_parse.return_value = mock_tree
        
        assets, _ = importer.parse_xml(Path("dummy.xml"))
        
        # Host should be skipped because of the 'if not ip_address: continue' fix
        assert len(assets) == 0
        mock_scope_validator.is_ip_in_scope.assert_not_called()

def test_parse_xml_no_address_element(mock_db, mock_scope_validator):
    """Test parsing Nmap XML where address element is missing entirely"""
    xml_content = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
<host>
<status state="up"/>
</host>
</nmaprun>
"""
    importer = NmapImporter(mock_db, mock_scope_validator)
    
    with patch("xml.etree.ElementTree.parse") as mock_parse:
        mock_tree = MagicMock()
        mock_tree.getroot.return_value = ET.fromstring(xml_content)
        mock_parse.return_value = mock_tree
        
        assets, _ = importer.parse_xml(Path("dummy.xml"))
        
        assert len(assets) == 0
        mock_scope_validator.is_ip_in_scope.assert_not_called()
