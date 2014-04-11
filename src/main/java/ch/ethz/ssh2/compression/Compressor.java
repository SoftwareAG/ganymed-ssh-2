package ch.ethz.ssh2.compression;

/**
 * @author Kenny Root
 * @version $Id:$
 */
public interface Compressor {
    int getBufferSize();

    int compress(byte[] buf, int start, int len, byte[] output);

    byte[] uncompress(byte[] buf, int start, int[] len);
}