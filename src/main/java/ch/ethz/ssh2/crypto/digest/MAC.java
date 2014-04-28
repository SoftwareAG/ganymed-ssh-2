/*
 * Copyright (c) 2006-2011 Christian Plattner. All rights reserved.
 * Please refer to the LICENSE.txt for licensing details.
 */
package ch.ethz.ssh2.crypto.digest;

import java.io.IOException;
import java.security.DigestException;

/**
 * MAC.
 *
 * @author Christian Plattner
 * @version 2.50, 03/15/10
 */
public final class MAC {
    private Digest mac;
    private int size;

    public static String[] getMacList() {
        // Higher priority first. Added SHA-2 algorithms as in RFC 6668
        return new String[]{"hmac-sha1-96", "hmac-sha1", "hmac-md5-96", "hmac-md5", "hmac-sha2-256", "hmac-sha2-512"};
    }

    public static void checkMacList(final String[] macs) {
        for(String m : macs) {
            getKeyLen(m);
        }
    }

    public static int getKeyLen(final String type) {
        if(type.equals("hmac-sha1")) {
            return 20;
        }
        if(type.equals("hmac-sha1-96")) {
            return 20;
        }
        if(type.equals("hmac-md5")) {
            return 16;
        }
        if(type.equals("hmac-md5-96")) {
            return 16;
        }
        if(type.equals("hmac-sha2-256")) {
            return 32;
        }
        if(type.equals("hmac-sha2-512")) {
            return 64;
        }
        throw new IllegalArgumentException(String.format("Unknown algorithm %s", type));
    }

    public MAC(final String type, final byte[] key) throws DigestException {
        if(type.equals("hmac-sha1")) {
            mac = new HMAC(new SHA1(), key, 20);
        }
        else if(type.equals("hmac-sha1-96")) {
            mac = new HMAC(new SHA1(), key, 12);
        }
        else if(type.equals("hmac-md5")) {
            mac = new HMAC(new MD5(), key, 16);
        }
        else if(type.equals("hmac-md5-96")) {
            mac = new HMAC(new MD5(), key, 12);
        }
        else if(type.equals("hmac-sha2-256")) {
            mac = new HMAC(new SHA256(), key, 32);
        }
        else if(type.equals("hmac-sha2-512")) {
            mac = new HMAC(new SHA512(), key, 64);
        }
        else {
            throw new IllegalArgumentException(String.format("Unknown algorithm %s", type));
        }
        size = mac.getDigestLength();
    }

    public final void initMac(final int seq) {
        mac.reset();
        mac.update((byte) (seq >> 24));
        mac.update((byte) (seq >> 16));
        mac.update((byte) (seq >> 8));
        mac.update((byte) (seq));
    }

    public final void update(byte[] packetdata, int off, int len) {
        mac.update(packetdata, off, len);
    }

    public final void getMac(byte[] out, int off) throws IOException {
        try {
            mac.digest(out, off);
        }
        catch(DigestException e) {
            throw new IOException(e);
        }
    }

    public final int size() {
        return size;
    }
}
