class A:
    def hello(self):
        print('A')
        super().hello()


class B:

    def hello(self):
        print('B')


class C:

    def hello(self):
        print('C')


class Full(A, B, C):

    def hello(self):
        super().hello()


class Parent:

    def hello(self):
        print('Parent')


class Child(Parent):

    def hello(self):
        print('Child')


class GrandKid(Child):

    def hello(self):
        print('GrandKid')


class X:
    abc = 'abc'
    xyz = None

    # def __init__(self):
    #     self.abc = 'abc'
    #     self.xyz = None

    def hello(self):
        print('zcy')


if __name__ == '__main__':
    print(issubclass(GrandKid, Parent))

    a = {
        'a': 'aa',
        'b': 'bb',
        'c': 'cc'
    }

    print(a.keys())
    print(type(a.keys()))

    for x in a:
        print(x)
        print(type(x))

