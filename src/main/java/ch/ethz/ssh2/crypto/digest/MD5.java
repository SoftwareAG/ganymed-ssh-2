/*
 * Copyright (c) 2006-2011 Christian Plattner. All rights reserved.
 * Please refer to the LICENSE.txt for licensing details.
 */
package ch.ethz.ssh2.crypto.digest;

import java.security.DigestException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * @version $Id$
 */
public final class MD5 implements Digest {

    private MessageDigest md;

    public MD5() {
        try {
            md = MessageDigest.getInstance("MD5");
        }
        catch(NoSuchAlgorithmException e) {
            throw new IllegalArgumentException(e);
        }
    }

    public final int getDigestLength() {
        return md.getDigestLength();
    }

    public final void reset() {
        md.reset();
    }

    public final void update(byte b[]) {
        this.update(b, 0, b.length);
    }

    public final void update(byte b[], int off, int len) {
        md.update(b, off, len);
    }

    public final void update(byte b) {
        md.update(b);
    }

    public final void digest(byte[] out) throws DigestException {
        this.digest(out, 0);
    }

    public final void digest(byte[] out, int off) throws DigestException {
        md.digest(out, off, out.length);
    }
}
