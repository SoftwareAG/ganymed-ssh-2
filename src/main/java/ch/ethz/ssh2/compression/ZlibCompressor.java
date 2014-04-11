package ch.ethz.ssh2.compression;

import com.jcraft.jzlib.JZlib;
import com.jcraft.jzlib.ZStream;

/**
 * @author Kenny Root
 * @version $Id:$
 */
public class ZlibCompressor implements Compressor {
    static private final int BUF_SIZE = 4096;
    static private final int LEVEL = 5;

    private ZStream deflate;
    private byte[] deflate_tmpbuf = new byte[BUF_SIZE];

    private ZStream inflate;
    private byte[] inflate_tmpbuf = new byte[BUF_SIZE];
    private byte[] inflated_buf;

    public ZlibCompressor() {
        deflate = new ZStream();
        inflate = new ZStream();

        deflate.deflateInit(LEVEL);
        inflate.inflateInit();
        inflated_buf = new byte[BUF_SIZE];
    }

    public int getBufferSize() {
        return BUF_SIZE;
    }

    public int compress(byte[] buf, int start, int len, byte[] output) {
        deflate.next_in = buf;
        deflate.next_in_index = start;
        deflate.avail_in = len - start;

        int status;
        int outputlen = start;

        do {
            deflate.next_out = deflate_tmpbuf;
            deflate.next_out_index = 0;
            deflate.avail_out = BUF_SIZE;
            status = deflate.deflate(JZlib.Z_PARTIAL_FLUSH);
            switch(status) {
                case JZlib.Z_OK:
                    System.arraycopy(deflate_tmpbuf, 0, output, outputlen, BUF_SIZE
                            - deflate.avail_out);
                    outputlen += (BUF_SIZE - deflate.avail_out);
                    break;
                default:
                    System.err.println("compress: deflate returnd " + status);
            }
        }
        while(deflate.avail_out == 0);
        return outputlen;
    }

    public byte[] uncompress(byte[] buffer, int start, int[] length) {
        int inflated_end = 0;

        inflate.next_in = buffer;
        inflate.next_in_index = start;
        inflate.avail_in = length[0];

        while(true) {
            inflate.next_out = inflate_tmpbuf;
            inflate.next_out_index = 0;
            inflate.avail_out = BUF_SIZE;
            int status = inflate.inflate(JZlib.Z_PARTIAL_FLUSH);
            switch(status) {
                case JZlib.Z_OK:
                    if(inflated_buf.length < inflated_end + BUF_SIZE
                            - inflate.avail_out) {
                        byte[] foo = new byte[inflated_end + BUF_SIZE
                                - inflate.avail_out];
                        System.arraycopy(inflated_buf, 0, foo, 0, inflated_end);
                        inflated_buf = foo;
                    }
                    System.arraycopy(inflate_tmpbuf, 0, inflated_buf, inflated_end,
                            BUF_SIZE - inflate.avail_out);
                    inflated_end += (BUF_SIZE - inflate.avail_out);
                    length[0] = inflated_end;
                    break;
                case JZlib.Z_BUF_ERROR:
                    if(inflated_end > buffer.length - start) {
                        byte[] foo = new byte[inflated_end + start];
                        System.arraycopy(buffer, 0, foo, 0, start);
                        System.arraycopy(inflated_buf, 0, foo, start, inflated_end);
                        buffer = foo;
                    }
                    else {
                        System.arraycopy(inflated_buf, 0, buffer, start,
                                inflated_end);
                    }
                    length[0] = inflated_end;
                    return buffer;
                default:
                    System.err.println("uncompress: inflate returnd " + status);
                    return null;
            }
        }
    }
}
