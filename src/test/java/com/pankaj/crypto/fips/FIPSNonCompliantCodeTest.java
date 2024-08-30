package com.pankaj.crypto.fips;

import org.junit.jupiter.api.Test;

import static com.pankaj.crypto.fips.FIPSNonCompliantCode.fipsNonCompliantKey;
import static org.junit.jupiter.api.Assertions.*;

class FIPSNonCompliantCodeTest {

    /**
     * FIPS compliance cannot be tested in Junit
     *
     */
    @Test
    void fipsNonCompliantKeyTest() {
        fipsNonCompliantKey();
    }
}