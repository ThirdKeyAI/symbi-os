// TEST ONLY: parsing succeeds, but schema validation must fail.
permit (principal, action == Symbi::Action::"not-declared", resource);
