from ecc import FieldElement, Point
import pytest


def test_ne():
    a = FieldElement(2, 31)
    b = FieldElement(2, 31)
    c = FieldElement(15, 31)
    assert a == b
    assert a != c
    assert not(a != b)

def test_add():
    a = FieldElement(2, 31)
    b = FieldElement(15, 31)
    assert a + b == FieldElement(17, 31)
    a = FieldElement(17, 31)
    b = FieldElement(21, 31)
    assert a + b == FieldElement(7, 31)

def test_sub():
    a = FieldElement(29, 31)
    b = FieldElement(4, 31)
    assert a - b == FieldElement(25, 31)
    a = FieldElement(15, 31)
    b = FieldElement(30, 31)
    assert a - b == FieldElement(16, 31)

def test_mul():
    a = FieldElement(24, 31)
    b = FieldElement(19, 31)
    assert a * b == FieldElement(22, 31)

def test_pow():
    a = FieldElement(17, 31)
    assert a**3 == FieldElement(15, 31)
    a = FieldElement(5, 31)
    b = FieldElement(18, 31)
    assert a**5 * b == FieldElement(16, 31)

def test_div():
    a = FieldElement(3, 31)
    b = FieldElement(24, 31)
    assert a / b == FieldElement(4, 31)
    a = FieldElement(17, 31)
    assert a**-3 == FieldElement(29, 31)
    a = FieldElement(4, 31)
    b = FieldElement(11, 31)
    assert a**-4 * b == FieldElement(13, 31)


def test_on_curve():
    prime = 223
    a = FieldElement(0, prime)
    b = FieldElement(7, prime)
    valid_points = ((192, 105), (17, 56), (1, 193))
    invalid_points = ((200, 119), (42, 99))
    for x_raw, y_raw in valid_points:
        x = FieldElement(x_raw, prime)
        y = FieldElement(y_raw, prime)
        Point(x, y, a, b)
    for x_raw, y_raw in invalid_points:
        x = FieldElement(x_raw, prime)
        y = FieldElement(y_raw, prime)
        with pytest.raises(ValueError):
            Point(x, y, a, b)

def test_point_add():
    prime = 223
    a = FieldElement(0, prime)
    b = FieldElement(7, prime)
    additions = ((192, 105, 17, 56, 170, 142), (47, 71, 117, 141, 60, 139), 
                 (143, 98, 76, 66, 47, 71))
    for _x1, _y1, _x2, _y2, _x3, _y3 in additions:
        x1 = FieldElement(_x1, prime)
        y1 = FieldElement(_y1, prime)
        p1 = Point(x1, y1, a, b)
        x2 = FieldElement(_x2, prime)
        y2 = FieldElement(_y2, prime)
        p2 = Point(x2, y2, a, b)
        x3 = FieldElement(_x3, prime)
        y3 = FieldElement(_y3, prime)
        p3 = Point(x3, y3, a, b)
        assert p1 + p2 == p3