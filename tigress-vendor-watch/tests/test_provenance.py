import sys; sys.path.insert(0, '..')
from core.provenance import Item, Tier, Verification, Confidence, rank, tag

# T1 primary but irrelevant -> must NOT beat a relevant T3
irrelevant_filing = Item("SEC EDGAR", "Vendor files routine 10-Q", "http://x",
                         Tier.T1_PRIMARY, relevance=0.1,
                         verification=Verification.OPENED).score()
# T3 press, corroborated, relevant -> should headline
live_event = Item("Reuters", "Vendor's main port shut by strike", "http://y",
                  Tier.T3_ESTABLISHED, relevance=0.9,
                  verification=Verification.CORROBORATED).score()
# T5 unverified rumor, relevant -> capped, no headline
rumor = Item("X post", "unconfirmed breach chatter", "http://z",
             Tier.T5_UNVETTED, relevance=0.8,
             verification=Verification.UNVERIFIED).score()

items = rank([irrelevant_filing, live_event, rumor])

print("RANKED ORDER:")
for it in items:
    print(f"  {tag(it):32} headline={it.headline_eligible!s:5} rel={it.relevance}  {it.title}")

# assertions the spine must satisfy
assert items[0].title.startswith("Vendor's main port"), "relevant T3 must lead"
assert not rumor.headline_eligible, "unverified T5 must be barred from headline"
assert irrelevant_filing.confidence == Confidence.HIGH, "T1 opened stays HIGH confidence"
assert not irrelevant_filing.headline_eligible, "but irrelevance bars the headline"
assert rumor.confidence == Confidence.LOW, "T5 capped low"
print("\nAll spine invariants hold.")
