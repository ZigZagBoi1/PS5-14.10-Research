import unittest
from prepare_sysent_map import prepare


class ReferenceMapTests(unittest.TestCase):
    def document(self):
        return {"kernel_base": "0x1000", "entries": [
            {"num": 0, "narg": 0, "sy_call": "0x1020", "sy_call_off": "0x20"},
            {"num": 1, "narg": 65535, "sy_call": "0x1020", "sy_call_off": "0x20"}]}

    def test_shared_target_and_implausible_count_are_preserved(self):
        rows = prepare(self.document())
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0][3], rows[1][3])
        self.assertEqual(rows[1][1], 65535)
        self.assertEqual(rows[1][4], "COUNT_IMPLAUSIBLE")

    def test_conflicting_coordinates_rejected(self):
        document = self.document()
        document["entries"][0]["sy_call"] = "0x1030"
        with self.assertRaises(ValueError):
            prepare(document)

    def test_repeated_selector_rejected(self):
        document = self.document()
        document["entries"][1]["num"] = 0
        with self.assertRaises(ValueError):
            prepare(document)

    def test_boolean_and_negative_offsets_rejected(self):
        for value in (True, -1):
            document = self.document()
            document["entries"][0]["sy_call_off"] = value
            with self.assertRaises(ValueError):
                prepare(document)


if __name__ == "__main__":
    unittest.main()
