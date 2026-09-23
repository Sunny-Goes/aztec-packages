// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.21;

import {TestBase} from "test/base/TestBase.sol";
import {Fr, ONE} from "src/honk/Fr.sol";
import {Honk} from "src/honk/HonkTypes.sol";
import {ecAdd, ecMul, mulWithSeperator} from "src/honk/utils.sol";

contract EcMulWrapper {
    function mul(Fr value, Honk.G1Point memory point) public view returns (Honk.G1Point memory) {
        return ecMul(value, point);
    }

    function mulWithSep(Honk.G1Point memory basePoint, Honk.G1Point memory other, Fr sep)
        public
        view
        returns (Honk.G1Point memory)
    {
        return mulWithSeperator(basePoint, other, sep);
    }
}

contract EcMulCanaryTest is TestBase {
    EcMulWrapper internal wrapper = new EcMulWrapper();

    // Generator of bn254 G1
    Honk.G1Point internal G = Honk.G1Point({x: 1, y: 2});
    // (1, 3): y^2 = 9 != x^3 + 3 = 4 (mod p). Not the point at infinity, so it
    // passes rejectPointAtInfinity, but the ecMul precompile rejects it.
    Honk.G1Point internal OFF_CURVE = Honk.G1Point({x: 1, y: 3});

    function test_ecMul_validPoint() public {
        Honk.G1Point memory doubled = wrapper.mul(Fr.wrap(2), G);
        Honk.G1Point memory added = ecAdd(G, G);
        assertEq(doubled.x, added.x);
        assertEq(doubled.y, added.y);
    }

    function test_ecMul_offCurvePoint_silentlyReturnsIdentity() public {
        // Canary: the precompile rejects the off-curve input, but the missing
        // success check lets execution continue and the pre-zeroed output
        // buffer surfaces as the point at infinity.
        Honk.G1Point memory result = wrapper.mul(Fr.wrap(5), OFF_CURVE);
        assertEq(result.x, 0);
        assertEq(result.y, 0);
    }

    function test_mulWithSeperator_validPoints() public {
        Honk.G1Point memory viaHelper = wrapper.mulWithSep(G, G, Fr.wrap(3));
        Honk.G1Point memory expected = ecAdd(ecMul(Fr.wrap(3), G), G);
        assertEq(viaHelper.x, expected.x);
        assertEq(viaHelper.y, expected.y);
    }

    // Exploit chain against BaseHonkVerifier / BaseZKHonkVerifier:
    //
    // The proof's pairing point object is the recursive-aggregation
    // accumulator: non-default points claim "this proof recursively verified
    // its predecessors". Upstream it is only checked against the point at
    // infinity, so off-curve coordinates reach the aggregation block.
    //
    //   P_final = mulWithSeperator(P_agg, P_other, sep)
    //           = sep * P_agg + ecMul(ONE, P_other)
    //
    // With an off-curve P_other the inner ecMul fails silently and returns
    // the identity, so the attacker's accumulator contribution vanishes:
    //
    //   P_final = sep * P_agg + O = sep * P_agg
    //
    // Doing this on both sides of the final check gives
    //
    //   e(sep * P_0, g2_a) * e(sep * P_1, g2_b)
    //     = (e(P_0, g2_a) * e(P_1, g2_b))^sep = 1^sep = 1
    //
    // for any otherwise-valid proof. The honest verifier reverts on the same
    // input (the ecAdd precompile rejects the off-curve point), while the
    // buggy verifier accepts a proof carrying a fabricated accumulator.
    function test_mulWithSeperator_offCurveOther_silentlyDropsContribution() public {
        Fr sep = Fr.wrap(7);
        Honk.G1Point memory aggregated = wrapper.mulWithSep(G, OFF_CURVE, sep);
        Honk.G1Point memory contributionDropped = ecMul(sep, G);
        assertEq(aggregated.x, contributionDropped.x);
        assertEq(aggregated.y, contributionDropped.y);
    }

    function test_ecAdd_acceptsSilentIdentity() public {
        // The final ecAdd/pairing precompiles accept (0,0) as the identity,
        // which is what lets the poisoned value sail through downstream checks.
        Honk.G1Point memory failedMul = wrapper.mul(Fr.wrap(5), OFF_CURVE);
        Honk.G1Point memory sum = ecAdd(G, failedMul);
        assertEq(sum.x, G.x);
        assertEq(sum.y, G.y);
    }
}
