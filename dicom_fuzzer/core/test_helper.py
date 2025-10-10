"""Helper functions for testing coverage tracking.

This module exists purely for testing purposes - to provide
traceable code in the core module that exercises the coverage tracker.
"""


def simple_function():
    """Simple function with multiple lines for tracing."""
    x = 1
    y = 2
    z = x + y
    return z


def another_function():
    """Another function with different code paths."""
    result = []
    for i in range(5):
        result.append(i * 2)
    return result


def conditional_function(value):
    """Function with conditional logic."""
    if value > 10:
        return "high"
    elif value > 5:
        return "medium"
    else:
        return "low"
