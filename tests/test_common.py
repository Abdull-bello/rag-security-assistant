import unittest

from corpus.common import fixed_window, recursive, split_text, SEPARATORS


class FixedWindowTests(unittest.TestCase):
    def test_windows_overlap_and_track_records(self):
        pieces = [("A", "w0 w1 w2 w3 w4"), ("B", "w5 w6 w7 w8 w9")]
        chunks = fixed_window(pieces, "x", window_words=4, overlap_words=1)
        self.assertEqual(len(chunks), 4)
        self.assertEqual(chunks[0].text, "w0 w1 w2 w3")
        self.assertEqual(chunks[1].text, "w3 w4 w5 w6")        # w3 repeats
        self.assertEqual(chunks[1].source_shortcodes, ["A", "B"])  # crosses a record
        self.assertEqual(chunks[0].chunk_id, "x-fixed-0000")

    def test_overlap_must_be_smaller_than_window(self):
        with self.assertRaises(ValueError):
            fixed_window([("A", "a b c")], "x", window_words=3, overlap_words=3)


class RecursiveTests(unittest.TestCase):
    def test_short_text_stays_whole(self):
        chunks = recursive([("A", "A short sentence.")], "x", max_chars=50)
        self.assertEqual([c.text for c in chunks], ["A short sentence."])

    def test_long_text_is_cut_under_the_limit(self):
        text = "First sentence here. Second sentence here. Third sentence here."
        chunks = recursive([("A", text)], "x", max_chars=30)
        self.assertGreater(len(chunks), 1)
        self.assertTrue(all(len(c.text) <= 30 for c in chunks))
        self.assertEqual([c.chunk_id for c in chunks],
                         [f"x-recursive-{n:04d}" for n in range(len(chunks))])
        self.assertTrue(all(c.source_shortcodes == ["A"] for c in chunks))

    def test_no_words_are_lost(self):
        text = "alpha beta gamma delta epsilon zeta eta theta " * 5
        parts = split_text(text.strip(), 40, SEPARATORS)
        self.assertEqual(" ".join(" ".join(parts).split()), " ".join(text.split()))


if __name__ == "__main__":
    unittest.main()
