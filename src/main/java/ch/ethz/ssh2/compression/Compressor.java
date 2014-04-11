package ch.ethz.ssh2.compression;

import java.io.IOException;

/**
 * @author Kenny Root
 * @version $Id$
 */
public interface Compressor {
    int getBufferSize();

    int compress(byte[] buf, int start, int len, byte[] output) throws IOException;

    byte[] uncompress(byte[] buf, int start, int[] len) throws IOException;
}