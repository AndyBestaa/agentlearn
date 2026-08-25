"""Dependency-free regression checks for the resume demo."""

from calculator import add


def main() -> None:
    cases = ((2, 3, 5), (-4, 9, 5), (0, 0, 0))
    for left, right, expected in cases:
        actual = add(left, right)
        assert actual == expected, (
            f"add({left}, {right}) returned {actual}; expected {expected}"
        )
    print("calculator regression: 3 checks passed")


if __name__ == "__main__":
    main()
