import unittest
from types import SimpleNamespace
from dlp.accessibility import inspect_tree, outermost_fields

ATSPI = SimpleNamespace(StateType=SimpleNamespace(EDITABLE='editable',FOCUSED='focused',SHOWING='showing'),Role=SimpleNamespace(PASSWORD_TEXT='password'))


class Node:
    def __init__(self, role='entry', states=(), children=()):
        self.role, self.states, self.children = role, states, children
        self.parent = None
        for child in children: child.parent = self
    def get_parent(self): return self.parent
    def get_state_set(self): return SimpleNamespace(contains=lambda value:value in self.states)
    def get_interfaces(self): return ['Accessible','Text']
    def get_role_name(self): return self.role
    def get_role(self): return self.role
    def get_child_count(self): return len(self.children)
    def get_child_at_index(self,index): return self.children[index]
    def get_name(self): raise AssertionError('Do not read names or message history')
    def get_text(self,*args): raise AssertionError('Discovery must not read content')


class AccessibilityTests(unittest.TestCase):
    def test_only_focused_showing_editable_nonpassword_candidates(self):
        draft=Node(states=('editable','focused','showing'))
        password=Node(role='password',states=('editable','focused','showing'))
        hidden=Node(states=('editable','focused'))
        history=Node(role='text',states=('showing',))
        root=Node(role='application',children=[draft,password,hidden,history])
        rows,candidates=inspect_tree(root,ATSPI)
        self.assertEqual(len(rows),5)
        self.assertEqual(candidates,[draft])
    def test_bounded_tree(self):
        root=Node(children=[Node() for _ in range(1000)])
        rows,candidates=inspect_tree(root,ATSPI,limit=5)
        self.assertEqual(len(rows),5)
    def test_empty_application_does_not_claim_support(self):
        rows,candidates=inspect_tree(Node(role='application'),ATSPI)
        self.assertEqual(candidates,[])
        self.assertEqual(rows[0]['children'],0)

    def test_deep_electron_field_is_one_candidate(self):
        mirrored=Node(states=('editable','showing'))
        draft=Node(states=('editable','focused','showing'),children=[mirrored])
        root=draft
        for _ in range(24):root=Node(role='section',children=[root])
        rows,candidates=inspect_tree(root,ATSPI,require_focus=False)
        self.assertEqual(candidates,[draft,mirrored])
        self.assertEqual(rows[-1]['depth'],25)
        self.assertEqual(outermost_fields(candidates),[draft])
        self.assertEqual(outermost_fields([mirrored]),[mirrored])

    def test_separate_fields_remain_ambiguous(self):
        first=Node(states=('editable','showing'))
        second=Node(states=('editable','showing'))
        _,candidates=inspect_tree(Node(role='application',children=[first,second]),ATSPI,require_focus=False)
        self.assertEqual(outermost_fields(candidates),[first,second])

    def test_password_descendants_are_not_candidates(self):
        child=Node(states=('editable','focused','showing'))
        root=Node(role='password',children=[child])
        _,candidates=inspect_tree(root,ATSPI,require_focus=False)
        self.assertEqual(candidates,[])
