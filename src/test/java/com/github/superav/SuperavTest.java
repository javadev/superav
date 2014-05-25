package com.github.superav;

import org.junit.Assert;
import org.junit.Test;

public class SuperavTest {

    @Test
    public void main() throws Exception {
        Superav.main(new String[] {});
        Superav.main(new String[] {".", "--r"});
    }
}