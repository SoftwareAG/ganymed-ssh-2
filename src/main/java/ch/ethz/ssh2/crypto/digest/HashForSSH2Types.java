/*
 * Copyright (c) 2006-2011 Christian Plattner. All rights reserved.
 * Please refer to the LICENSE.txt for licensing details.
 */
package ch.ethz.ssh2.crypto.digest;

import java.io.IOException;
import java.math.BigInteger;
import java.security.DigestException;

/**
 * HashForSSH2Types.
 *
 * @author Christian Plattner
 * @version 2.50, 03/15/10
 */
public class HashForSSH2Types {
    Digest md;

    public HashForSSH2Types(Digest md) {
        this.md = md;
    }

    public HashForSSH2Types(String type) {
        if(type.equals("SHA1")) {
            md = new SHA1();
        }
        else if(type.equals("SHA2")) {
            md = new SHA256();
        }
        else if(type.equals("MD5")) {
            md = new MD5();
        }
        else {
            throw new IllegalArgumentException(String.format("Unknown algorithm %s", type));
        }
    }

    public void updateByte(byte b) {
        md.update(b);
    }

    public void updateBytes(byte[] b) {
        md.update(b);
    }

    public void updateUINT32(int v) {
        md.update((byte) (v >> 24));
        md.update((byte) (v >> 16));
        md.update((byte) (v >> 8));
        md.update((byte) (v));
    }

    public void updateByteString(byte[] b) {
        updateUINT32(b.length);
        updateBytes(b);
    }

    public void updateBigInt(BigInteger b) {
        updateByteString(b.toByteArray());
    }

    public void reset() {
        md.reset();
    }

    public int getDigestLength() {
        return md.getDigestLength();
    }

    public byte[] getDigest() throws IOException {
        byte[] tmp = new byte[md.getDigestLength()];
        getDigest(tmp);
        return tmp;
    }

    public void getDigest(byte[] out) throws IOException {
        try {
            getDigest(out, 0);
        }
        catch(DigestException e) {
            throw new IOException(e);
        }
    }

    public void getDigest(byte[] out, int off) throws DigestException {
        md.digest(out, off);
    }
}
