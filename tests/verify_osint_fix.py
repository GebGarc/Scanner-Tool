
# Mocking the OSINTResult and logic from osint.py
class MockResult:
    def __init__(self, raw_data):
        self.raw_data = raw_data

def test_logic(raw_data):
    # This is the logic I implemented in osint.py
    data_to_check = raw_data if isinstance(raw_data, dict) else {}
    snapshots_len = len(data_to_check.get('snapshots', []))
    return snapshots_len

# Test case 1: raw_data is a dict with snapshots
res1 = test_logic({'snapshots': [1, 2, 3]})
print(f"Test case 1 (dict with snapshots): {res1} (expected 3)")

# Test case 2: raw_data is None
res2 = test_logic(None)
print(f"Test case 2 (None): {res2} (expected 0)")

# Test case 3: raw_data is an empty dict
res3 = test_logic({})
print(f"Test case 3 (empty dict): {res3} (expected 0)")

# Test case 4: raw_data is something else
res4 = test_logic("not a dict")
print(f"Test case 4 (string): {res4} (expected 0)")

if res1 == 3 and res2 == 0 and res3 == 0 and res4 == 0:
    print("\nVerification SUCCESSFUL")
else:
    print("\nVerification FAILED")
