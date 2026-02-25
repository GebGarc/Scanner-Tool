import pytest
from unittest.mock import MagicMock, patch
from app.modules.osint import WHOISService

@pytest.mark.asyncio
async def test_whois_lookup_domain_dictionary_access():
    """Test that lookup_domain correctly uses dictionary access on the whois result."""
    service = WHOISService()
    domain = "example.com"
    
    # Mock the whois.whois return value.
    # The python-whois return object is dict-like.
    mock_whois_data = {
        'domain_name': 'example.com',
        'registrar': 'Example Registrar',
        'whois_server': 'whois.example.com',
        'creation_date': None,
        'expiration_date': None,
        'updated_date': None,
        'status': 'ok',
        'name_servers': [],
        'emails': [],
        'org': 'Example Org',
        'address': '123 Example St',
        'city': 'Example City',
        'state': 'EX',
        'country': 'US'
    }
    
    # We need to simulate the object having a .get method since it's dict-like
    mock_entry = MagicMock()
    mock_entry.get.side_effect = mock_whois_data.get
    
    with patch('whois.whois', return_value=mock_entry):
        result = await service.lookup_domain(domain)
        
        assert result['domain_name'] == 'example.com'
        assert result['registrar'] == 'Example Registrar'
        assert result['org'] == 'Example Org'
        assert 'error' not in result
