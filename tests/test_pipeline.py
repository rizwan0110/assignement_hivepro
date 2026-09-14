from data_loader import master
from risk_engine import scored, top_5


def test_master_table_row_count():
    """
    The master table should contain one row per vulnerability.
    The source vulnerability dataset contains 114 records.
    """
    assert len(master) == 114


def test_risk_scores_within_range():
    """
    Every risk score should stay within the designed
    0-100 scoring range.
    """
    assert scored["risk_score"].between(0, 100).all()


def test_top_5_contains_five_risks():
    """
    The final ranking should return exactly five risks.
    """
    assert len(top_5) == 5


def test_risk_ranking_is_descending():
    """
    Risk scores should be ordered from highest to lowest.
    """
    scores = top_5["risk_score"].tolist()

    assert scores == sorted(
        scores,
        reverse=True
    )


def test_exposure_mismatch_detected():
    """
    The supplied dataset contains at least one disagreement
    between asset inventory exposure and vulnerability
    scanner exposure.
    """
    mismatches = scored[
        scored["exposure_mismatch"] == True
    ]

    assert len(mismatches) >= 1


def test_known_exposure_mismatch():
    """
    Validate the specific data-quality issue discovered
    during analysis.
    """

    mismatch = scored[
        scored["vuln_id"] == "V-2014"
    ]

    assert not mismatch.empty

    assert bool(
        mismatch.iloc[0]["exposure_mismatch"]
    ) is True