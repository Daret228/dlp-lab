import unittest
from dlp.sensitive_values_v4 import rule_predict, hybrid_predict
from dlp.ml_baseline import fit


class ValueEvidenceTests(unittest.TestCase):
    def test_secret_discussion_and_placeholders(self):
        for text in [
            'Обнови пароль до 2027 года.',
            'Пароль не указан; номер заявки 483726.',
            'PASSWORD=[REDACTED]; USER=example_staff;',
            'DB_PASSWORD=${ENV_SECRET}',
            'Поле password должно содержать минимум: 1234 символа.',
            'Логин lab_worker, пароль не передаю.',
            'Password field is empty. Contact the administrator.',
        ]:
            with self.subTest(text=text): self.assertEqual(rule_predict(text),[])

    def test_explicit_plain_and_numeric_secrets(self):
        for text in ['Пароль: берёза', 'Пароль = кот', 'Password: abc',
                     'Пароль: 381927', 'Секретная фраза: «тихий ветер над рекой»',
                     'Код входа в учебную анкету 005218.',
                     'Пароль не указан; API_KEY=q7N3rW9tM2kV6pL8']:
            with self.subTest(text=text):self.assertIn('credentials',rule_predict(text))

    def test_passport_does_not_capture_order_or_phone(self):
        for text in ['Нужен паспорт; номер заказа 0051627384.',
                     'Паспорт забыл, телефон 0012345678.',
                     'Паспорт нужен позже, инвентарный номер 0012345678.']:
            with self.subTest(text=text):self.assertNotIn('passport',rule_predict(text))

    def test_passport_forms(self):
        for text in ['Паспорт 0051 627384', 'Паспорт\nСерия 00 51\nНомер 627384',
                     'Паспорт; серия 0051; номер 627384']:
            self.assertIn('passport',rule_predict(text))

    def test_financial_public_and_private(self):
        self.assertEqual(rule_predict('Публичная вакансия: оклад 70000 рублей.'),[])
        self.assertIn('financial',rule_predict('Мой оклад 70000 рублей.'))
        self.assertIn('financial',rule_predict('Публичная вакансия: 70000 рублей; мой оклад 95000 рублей.'))

    def test_multiple_categories(self):
        self.assertEqual(rule_predict('Паспорт 0051 627384; зарплата 86000 рублей; пароль: берёза'),
                         ['credentials','financial','passport'])

    def test_limit_is_error_not_safe(self):
        with self.assertRaises(ValueError):rule_predict('я'*9000)

    def test_ml_cannot_flag_without_value_gate(self):
        rows=[dict(split='train',text=t,labels=l) for t,l in [
            ('money bank',['financial']),('passport',['passport']),('password',['credentials']),('hello',[])]]
        model=fit(rows)
        for m in model['models'].values():m['threshold']=-1e9
        self.assertEqual(hybrid_predict(model,'Нужно сменить пароль и принести паспорт.'),[])
