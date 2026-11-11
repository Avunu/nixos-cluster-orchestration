# The mutation helper, spliced into a VM test's script after a prelude that sets
# MUTANT (`MUTANT = "${mutant}"`, default ""). A test file is shaped like this:
#
#   def main():
#       control("some-assertion", ok, detail)
#       ...
#   run_main(main)
#
# A mutant is the same test with `extraModule` removing one control and `mutant`
# naming the assertion that must go false. Mutants live in
# legacyPackages.<system>.mutants, not in `checks`; tests/run-mutants.sh runs them.


class MutationProven(Exception):
    pass


def control(name, ok, detail=""):
    """Every security assertion goes through here. A mutant build removes one
    control and sets MUTANT to the assertion that must flip. It passes only if
    that assertion goes false, so a mutant is a normal green build and needs no
    inverted exit codes or log parsing."""
    if MUTANT == name:
        if ok:
            raise Exception(f"mutant {name}: control removed and the check still passed. {detail}")
        print(f"##MUTATION-PROVEN## {name}: {detail}")
        raise MutationProven()
    if not ok:
        raise Exception(f"control {name} failed: {detail}")


def run_main(main):
    """What a test's script ends with. A mutant whose named control never runs (a name
    misspelt or renamed, or a control behind a branch this run doesn't take) would
    otherwise finish main() normally and build green, proving nothing. So a mutant build
    passes only by raising MutationProven, and the normal build only by finishing."""
    # Read through globals(): the test driver's typechecker would otherwise see a normal
    # run's MUTANT = "" as always false, call the raise unreachable, and fail the build.
    try:
        main()
    except MutationProven:
        return
    if globals()["MUTANT"]:
        raise Exception(f"mutant {MUTANT}: its control was never reached, so nothing was proven")
