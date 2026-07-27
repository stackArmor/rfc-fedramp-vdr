import unittest
from itertools import product

from pain_ceiling import (
    DEBILITATING_THRESHOLD,
    aggregate_profiles,
    all_profiles,
    debilitating,
    effective_requirements,
    objective_max,
    severity,
)


class PainCeilingProperties(unittest.TestCase):
    def test_unconstrained_lattice_has_70_debilitating_states(self):
        impacts = tuple(product(("N", "L", "H"), repeat=3))
        requirements = tuple(all_profiles())
        count = sum(
            debilitating(impact, requirement)
            for impact in impacts
            for requirement in requirements
        )
        self.assertEqual(count, 70)

    def test_no_high_ceiling_dimension_means_no_debilitating_result(self):
        impacts = tuple(product(("N", "L", "H"), repeat=3))
        archetypes = tuple(all_profiles())
        ceilings = tuple(product(("L", "M"), repeat=3))

        for impact, archetype, ceiling in product(impacts, archetypes, ceilings):
            effective = effective_requirements(archetype, ceiling)
            self.assertFalse(debilitating(impact, effective))

    def test_all_moderate_maximum_is_below_debilitating(self):
        maximum = severity(("H", "H", "H"), ("M", "M", "M"))
        self.assertAlmostEqual(maximum, 0.914816 / 0.995904, places=15)
        self.assertLess(maximum, DEBILITATING_THRESHOLD)

    def test_debilitating_requires_at_least_one_effective_high(self):
        impacts = tuple(product(("N", "L", "H"), repeat=3))
        requirements = tuple(all_profiles())

        for impact, requirement in product(impacts, requirements):
            if debilitating(impact, requirement):
                self.assertIn("H", requirement)

    def test_ceiling_never_raises_an_archetype_requirement(self):
        rank = {"L": 1, "M": 2, "H": 3}
        for archetype, ceiling in product(all_profiles(), all_profiles()):
            effective = effective_requirements(archetype, ceiling)
            self.assertTrue(
                all(
                    rank[value] <= rank[raw]
                    for value, raw in zip(effective, archetype)
                )
            )

    def test_shared_asset_ceiling_is_monotonic(self):
        agency_one = ("M", "M", "L")
        agency_two = ("L", "H", "M")

        self.assertEqual(aggregate_profiles((agency_one,)), agency_one)
        self.assertEqual(
            aggregate_profiles((agency_one, agency_two)),
            ("M", "H", "M"),
        )

    def test_agency_elsewhere_does_not_change_single_agency_asset(self):
        dedicated_asset_agencies = (("M", "M", "L"),)
        unrelated_agency = ("H", "L", "H")

        before = aggregate_profiles(dedicated_asset_agencies)
        after = aggregate_profiles(dedicated_asset_agencies)
        self.assertEqual(before, after)
        self.assertNotIn(unrelated_agency, dedicated_asset_agencies)

    def test_any_high_objective_makes_overall_fips_impact_high_without_flattening(self):
        vector = ("H", "M", "L")
        self.assertEqual(objective_max(*vector), "H")
        self.assertNotEqual(vector, ("H", "H", "H"))

    def test_vector_min_can_claim_compatibility_without_type_overlap(self):
        cso_types = {"critical-infrastructure"}
        agency_types = {"health-care-delivery"}
        cso_aggregate = ("H", "M", "M")
        agency_aggregate = ("H", "M", "M")

        self.assertFalse(cso_types.intersection(agency_types))
        self.assertEqual(
            effective_requirements(cso_aggregate, agency_aggregate),
            ("H", "M", "M"),
        )


if __name__ == "__main__":
    unittest.main()
