package ch.ethz.ssh2;

/**
 * @version $Id$
 */
public class SFTPFileHandle {

    private final SFTPClient client;

    private final byte[] handle;

    protected SFTPFileHandle(final SFTPClient client, final byte[] handle) {
        this.client = client;
        this.handle = handle;
    }

    /**
     * Get the SFTPv3Client instance which created this handle.
     *
     * @return A SFTPv3Client instance.
     */
    public SFTPClient getClient() {
        return client;
    }

    public byte[] getHandle() {
        return handle;
    }
}
