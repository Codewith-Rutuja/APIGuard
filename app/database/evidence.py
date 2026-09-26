from .db import get_apiguard_connection
from ..utils import utc_now


def save_evidence(
    finding_id,
    request_data=None,
    response_data=None,
    expected_behavior=None,
    observed_behavior=None,
):
    connection = get_apiguard_connection()

    try:
        cursor = connection.execute(
            """
            INSERT INTO evidence (
                finding_id,
                request_data,
                response_data,
                expected_behavior,
                observed_behavior,
                captured_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                finding_id,
                request_data,
                response_data,
                expected_behavior,
                observed_behavior,
                utc_now(),
            ),
        )

        connection.commit()
        return cursor.lastrowid

    finally:
        connection.close()
