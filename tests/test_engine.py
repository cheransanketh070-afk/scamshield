import unittest

from scamshield import Engine, LIKELY_SCAM, LOW_RISK, SUSPICIOUS, analyze
from scamshield.urls import find_urls

ENGINE = Engine()


def ids(report):
    return {f.rule_id for f in report.findings}


class RuleSelfTest(unittest.TestCase):
    """Every rule must ship examples, and those examples must trigger it."""

    def test_every_rule_has_examples_that_fire(self):
        for rule in ENGINE.rules:
            self.assertTrue(rule.examples, f"{rule.id} has no examples")
            for example in rule.examples:
                self.assertIn(rule.id, ids(ENGINE.analyze(example)),
                              f"{rule.id} did not fire on {example!r}")

    def test_rule_ids_are_unique(self):
        found = [r.id for r in ENGINE.rules]
        self.assertEqual(len(found), len(set(found)))


class Verdicts(unittest.TestCase):
    def test_bank_phishing_is_scam(self):
        r = analyze("URGENT: Your bank account will be suspended within 24 hours. "
                    "Verify your account now at http://secure-hsbc-login.xyz/verify")
        self.assertEqual(r.verdict, LIKELY_SCAM)
        self.assertGreaterEqual(r.score, 90)

    def test_parcel_fee_is_scam(self):
        r = analyze("Your package is on hold. Pay a $1.99 redelivery fee at bit.ly/3xYz")
        self.assertEqual(r.verdict, LIKELY_SCAM)

    def test_prize_with_fee_is_scam(self):
        r = analyze("Congratulations! You have won the lottery. Pay the processing fee to claim.")
        self.assertEqual(r.verdict, LIKELY_SCAM)

    def test_job_offer_is_suspicious(self):
        r = analyze("Work from home! Earn $300 per day. Message us on WhatsApp.")
        self.assertEqual(r.verdict, SUSPICIOUS)

    def test_genuine_otp_is_low_risk(self):
        r = analyze("Your OTP is 482913. Do not share it with anyone.")
        self.assertEqual(r.verdict, LOW_RISK)
        self.assertEqual(r.score, 0)

    def test_asking_for_otp_is_flagged(self):
        self.assertIn("credentials.en.ask", ids(analyze("Please share your OTP with our agent")))

    def test_normal_chat_is_low_risk(self):
        self.assertEqual(analyze("Are we still on for lunch at 1pm tomorrow?").verdict, LOW_RISK)

    def test_empty_input(self):
        r = analyze("")
        self.assertEqual((r.score, r.verdict), (0, LOW_RISK))

    def test_score_is_clamped(self):
        r = analyze("URGENT you won the lottery, verify your account, share your OTP, "
                    "pay the processing fee in bitcoin, legal action, http://1.2.3.4/x")
        self.assertEqual(r.score, 100)


class Languages(unittest.TestCase):
    def test_spanish(self):
        r = analyze("Felicidades, has ganado un premio. Verifica tu cuenta ahora")
        self.assertEqual(r.verdict, LIKELY_SCAM)

    def test_sinhala_script_detected(self):
        r = analyze("ඔබට ලොතරැයි ජයග්රහණයක් ලැබී ඇත. ඔබගේ OTP එවන්න")
        self.assertEqual(r.script, "sinhala")
        self.assertIn("prize.si", ids(r))


class Links(unittest.TestCase):
    def kinds(self, text):
        return {f.rule_id for f in find_urls(text)}

    def test_shortener(self):
        self.assertIn("url.shortener", self.kinds("see bit.ly/abc123"))

    def test_lookalike_brand(self):
        self.assertIn("url.brand.paypal", self.kinds("https://paypa1.com/signin"))

    def test_brand_in_subdomain_of_other_site(self):
        self.assertIn("url.brand.paypal", self.kinds("https://paypal.com.verify-id.xyz/login"))

    def test_real_brand_domain_is_clean(self):
        self.assertEqual(self.kinds("https://www.amazon.com/orders and https://aws.amazon.com"), set())

    def test_unrelated_words_are_not_brands(self):
        self.assertEqual(self.kinds("visit pineapple.com or apply.com"), set())

    def test_ip_address(self):
        self.assertIn("url.ip", self.kinds("http://192.168.4.4/login"))

    def test_userinfo_trick(self):
        self.assertIn("url.userinfo", self.kinds("https://paypal.com@evil.example.org/"))

    def test_email_is_not_a_link(self):
        self.assertEqual(self.kinds("write to john@evil-shop.top"), set())

    def test_trailing_punctuation_is_trimmed(self):
        f = find_urls("Go to https://bit.ly/abc, now.")[0]
        self.assertEqual(f.evidence, "https://bit.ly/abc")

    def test_offsets_point_at_the_link(self):
        text = "click bit.ly/abc now"
        f = find_urls(text)[0]
        self.assertEqual(text[f.start:f.end], "bit.ly/abc")


class Report(unittest.TestCase):
    def test_json_shape(self):
        d = analyze("Pay the processing fee").to_dict()
        self.assertEqual(set(d), {"score", "verdict", "headline", "findings", "advice", "script"})
        self.assertTrue(d["advice"])

    def test_evidence_offsets_match_text(self):
        text = "Please pay the processing fee today"
        for f in analyze(text).findings:
            if f.start >= 0:
                self.assertEqual(text[f.start:f.end][:80], f.evidence)


if __name__ == "__main__":
    unittest.main()
