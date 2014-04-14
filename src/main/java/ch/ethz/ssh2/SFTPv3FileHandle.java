/*
 * Copyright (c) 2006-2011 Christian Plattner. All rights reserved.
 * Please refer to the LICENSE.txt for licensing details.
 */
package ch.ethz.ssh2;

/**
 * A <code>SFTPv3FileHandle</code>.
 *
 * @author Christian Plattner
 * @version 2.50, 03/15/10
 */
public class SFTPv3FileHandle extends SFTPFileHandle {
    protected SFTPv3FileHandle(final SFTPv3Client client, final byte[] handle) {
        super(client, handle);
    }
}
