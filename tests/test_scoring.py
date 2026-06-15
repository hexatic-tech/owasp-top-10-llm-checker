from src.core import scoring


def test_all_pass_is_pass():
    assert scoring.category_status(["PASS", "PASS"]) == scoring.PASS


def test_all_fail_is_fail():
    assert scoring.category_status(["FAIL", "FAIL"]) == scoring.FAIL


def test_all_error_is_error():
    assert scoring.category_status(["ERROR", "ERROR"]) == scoring.ERROR


def test_pass_fail_mix_is_mixed():
    assert scoring.category_status(["PASS", "FAIL"]) == scoring.MIXED


def test_warning_is_mixed():
    assert scoring.category_status(["WARNING"]) == scoring.MIXED


def test_empty_is_error():
    assert scoring.category_status([]) == scoring.ERROR


def test_score_all_pass():
    score = scoring.security_score(["PASS", "PASS", "PASS"])
    assert score.passed == 3
    assert score.display == "3/3 secure"


def test_score_all_error_not_evaluated():
    score = scoring.security_score(["ERROR", "ERROR"])
    assert score.display == "Not evaluated"


def test_score_counts():
    score = scoring.security_score(["PASS", "FAIL", "MIXED", "ERROR"])
    assert (score.passed, score.failed, score.mixed, score.errors) == (1, 1, 1, 1)
    assert score.total == 4
