import json
import pytest
from password_analyzer import analyze, generate_password

@pytest.mark.parametrize('password', ['aA1!', 'Password123!', 'aaaaaaaaaaaaaaaa'])
def test_predictable_secrets_are_not_strong(password):
    result = analyze(password)
    assert result['score'] <= 2
    assert password not in json.dumps(result)
    assert 'password' not in result and 'hash_sha256' not in result
    assert result['breach_status'] == 'Not checked'

@pytest.mark.parametrize('length', [8,15,24,64,128])
def test_generator_exact_length_and_groups(length):
    password = generate_password(length)
    assert len(password) == length
    assert any(c.isupper() for c in password)
    assert any(c.islower() for c in password)
    assert any(c.isdigit() for c in password)
    assert any(not c.isalnum() for c in password)

@pytest.mark.parametrize('length', [0,1,3,129,True,3.5])
def test_generator_invalid_lengths_fail(length):
    with pytest.raises(ValueError): generate_password(length)

def test_no_enabled_character_group_fails():
    with pytest.raises(ValueError): generate_password(24,False,False,False,False)

def test_no_truncation_or_persistence(tmp_path,monkeypatch):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(ValueError): analyze('a'*129)
    with pytest.raises(ValueError): analyze('')
    analyze('harbor-fixture-example-only')
    assert list(tmp_path.iterdir()) == []
