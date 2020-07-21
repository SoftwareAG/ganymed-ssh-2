package ch.ethz.ssh2.crypto.digest;

import java.security.DigestException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SHA2 implements Digest {

    private MessageDigest md = null;

    public SHA2(int keyLen) {
        try {
            md = MessageDigest.getInstance("SHA-" + keyLen);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public int getDigestLength() {
        return md.getDigestLength();
    }

    @Override
    public void update(byte b) {
        md.update(b);
    }

    @Override
    public void update(byte[] b) {
        md.update(b);
    }

    @Override
    public void update(byte[] b, int off, int len) {
        md.update(b, off, len);
    }

    @Override
    public void reset() {
        md.reset();
    }

    @Override
    public void digest(byte[] out) {
        try {
            md.digest(out, 0, out.length);
        } catch (DigestException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void digest(byte[] out, int off) {
        try {
            md.digest(out, off, out.length - off);
        } catch (DigestException e) {
            throw new RuntimeException(e);
        }
    }
}
